package com.dex.enc

import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.common.collect.ImmutableSet
import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcode
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.builder.MutableMethodImplementation
import org.jf.dexlib2.builder.instruction.*
import org.jf.dexlib2.iface.*
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.StringReference
import org.jf.dexlib2.immutable.*
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference
import org.jf.dexlib2.immutable.reference.ImmutableStringReference
import org.jf.dexlib2.immutable.reference.ImmutableTypeReference
import org.jf.dexlib2.rewriter.*
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    private lateinit var tvLog: TextView
    private var selectedApkUri: Uri? = null
    private val encryptKey = SecretKeySpec("MySecureKey12345".toByteArray(), "AES")
    private val handler = Handler(Looper.getMainLooper())

    private val openDocumentLauncher = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri?.let {
            selectedApkUri = it
            appendLog("已选择 APK: ${it.lastPathSegment}")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvLog = findViewById(R.id.tv_log)
        findViewById<Button>(R.id.btn_select_apk).setOnClickListener { openDocumentLauncher.launch("*/*") }
        findViewById<Button>(R.id.btn_encrypt).setOnClickListener {
            if (selectedApkUri == null) { appendLog("请先选择一个 APK 文件"); return@setOnClickListener }
            showEncryptModeDialog()
        }
    }

    private fun showEncryptModeDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("选择加密模式")
            .setItems(arrayOf("普通加密", "高级加密 (防字符串解密)")) { _, which ->
                showDexSelectionDialog(if (which == 0) "normal" else "advanced")
            }.show()
    }

    private fun showDexSelectionDialog(mode: String) {
        Thread {
            val uri = selectedApkUri ?: return@Thread
            val cacheFile = File(cacheDir, "input.apk")
            try {
                contentResolver.openInputStream(uri)?.use { input -> FileOutputStream(cacheFile).use { output -> input.copyTo(output) } }
                val dexEntries = mutableListOf<String>()
                ZipFile(cacheFile).use { zip -> val entries = zip.entries(); while (entries.hasMoreElements()) { val name = entries.nextElement().name; if (name.endsWith(".dex")) dexEntries.add(name) } }
                cacheFile.delete()
                if (dexEntries.isEmpty()) { appendLog("APK 中未找到任何 .dex 文件"); return@Thread }
                val hasMainDex = dexEntries.contains("classes.dex")
                handler.post { showMultiChoiceDialog(dexEntries.toTypedArray(), hasMainDex, mode) }
            } catch (e: Exception) { appendLog("解析 APK 失败: ${e.message}") }
        }.start()
    }

    private fun showMultiChoiceDialog(dexNames: Array<String>, hasMainDex: Boolean, mode: String) {
        val checkedItems = BooleanArray(dexNames.size) { true }
        if (hasMainDex) checkedItems[dexNames.indexOf("classes.dex")] = true
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("选择要加密的 DEX 文件")
            .setMultiChoiceItems(dexNames, checkedItems) { _, _, _ -> }
            .setNegativeButton("取消") { dialog, _ -> dialog.cancel() }
            .setPositiveButton("加密") { _, _ ->
                val selectedDex = dexNames.filterIndexed { index, _ -> checkedItems[index] }
                if (selectedDex.isEmpty()) { appendLog("未选中任何 DEX 文件"); return@setPositiveButton }
                Thread { try { encryptAllStrings(selectedDex, mode) } catch (e: Exception) { handler.post { appendLog("加密失败: ${e.message}") } } }.start()
            }.show()
    }

    private fun encryptAllStrings(selectedDex: List<String>, mode: String) {
        handler.post { appendLog("开始${if (mode == "advanced") "高级" else "普通"}字符串加密...") }
        val inputApk = File(cacheDir, "input.apk")
        if (!inputApk.exists()) copyUriToCache(selectedApkUri!!)
        handler.post { appendLog("已缓存 APK") }
        
        val modifiedDexMap = mutableMapOf<String, ByteArray>()
        val stringIndexMap = mutableMapOf<String, Int>()
        
        if (mode == "advanced") {
            handler.post { appendLog("正在分析字符串...") }
            val tempStrings = mutableListOf<String>()
            for (dexName in selectedDex) {
                val bytes = ZipFile(inputApk).use { it.getInputStream(it.getEntry(dexName)!!).readBytes() }
                val tempFile = File(cacheDir, "temp.dex"); tempFile.writeBytes(bytes)
                val dex = DexFileFactory.loadDexFile(tempFile, Opcodes.getDefault())
                for (classDef in dex.classes) {
                    if (classDef.type == "Lcom/secure/Decryptor;" || classDef.type == "Lcom/secure/StringPool;") continue
                    for (method in classDef.methods) {
                        method.implementation?.let { impl -> for (inst in impl.instructions) { if (inst is ReferenceInstruction && inst.reference is StringReference) { val str = (inst.reference as StringReference).string; if (str !in tempStrings) tempStrings.add(str) } } }
                    }
                }
                tempFile.delete()
            }
            tempStrings.forEachIndexed { index, s -> stringIndexMap[s] = index }
            handler.post { appendLog("发现 ${stringIndexMap.size} 个字符串") }
        }

        for ((index, dexName) in selectedDex.withIndex()) {
            handler.post { appendLog("正在处理 $dexName...") }
            val originalBytes = ZipFile(inputApk).use { it.getInputStream(it.getEntry(dexName)!!).readBytes() }
            modifiedDexMap[dexName] = processSingleDex(originalBytes, index == 0, mode, stringIndexMap)
            handler.post { appendLog("$dexName 处理完成") }
        }

        handler.post { appendLog("正在重新打包 APK...") }
        
        
        val outputDir = getSafeOutputDirectory()
        val rawName = selectedApkUri?.lastPathSegment ?: "encrypted.apk"
        val outputName = if (rawName.endsWith(".apk", true)) rawName.substringBeforeLast(".") + "_enc.apk" else "${rawName}_enc.apk"
        val outputApk = File(outputDir, outputName)
        
        repackApk(inputApk, modifiedDexMap, outputApk)
        inputApk.delete()
        handler.post { appendLog("加密成功！\n输出路径: ${outputApk.absolutePath}") }
    }

    
    private fun getSafeOutputDirectory(): File {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) {
                val dir = Environment.getExternalStorageDirectory()
                if (tryWriteTest(dir)) return dir
            }
            return getExternalFilesDir(null) ?: cacheDir
        }
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) {
            val dir = Environment.getExternalStorageDirectory()
            if (tryWriteTest(dir)) return dir
        }
        return getExternalFilesDir(null) ?: cacheDir
    }

    
    private fun tryWriteTest(dir: File): Boolean {
        return try {
            val testFile = File(dir, ".enc_test_${System.currentTimeMillis()}")
            FileOutputStream(testFile).use { it.write(1) }
            testFile.delete()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun processSingleDex(dexBytes: ByteArray, injectDecryptor: Boolean, mode: String, stringIndexMap: Map<String, Int>): ByteArray {
        val tempIn = File(cacheDir, "temp_in.dex"); tempIn.writeBytes(dexBytes)
        val opcodes = Opcodes.getDefault()
        val originalDex = DexFileFactory.loadDexFile(tempIn, opcodes)
        val rewrittenDex = createDexRewriter(mode, stringIndexMap).getDexFileRewriter().rewrite(originalDex)
        val allClasses = rewrittenDex.classes.mapTo(mutableSetOf<ClassDef>()) { it }
        if (injectDecryptor) {
            allClasses.add(buildDecryptorClass())
            if (mode == "advanced") allClasses.add(buildStringPoolClass(stringIndexMap))
        }
        val tempOut = File(cacheDir, "temp_out.dex")
        DexFileFactory.writeDexFile(tempOut.absolutePath, ImmutableDexFile(opcodes, allClasses))
        val result = tempOut.readBytes()
        tempIn.delete(); tempOut.delete()
        return result
    }

    private fun copyUriToCache(uri: Uri): File {
        val cacheFile = File(cacheDir, "input.apk")
        contentResolver.openInputStream(uri)?.use { input -> FileOutputStream(cacheFile).use { output -> input.copyTo(output) } }
        return cacheFile
    }

    private fun buildStringPoolClass(stringIndexMap: Map<String, Int>): ClassDef {
        val classType = "Lcom/secure/StringPool;"
        val encStrings = stringIndexMap.keys.map { str -> try { val c = Cipher.getInstance("AES/ECB/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE, encryptKey); Base64.encodeToString(c.doFinal(str.toByteArray()), Base64.NO_WRAP) } catch (e: Exception) { str } }
        val arrayField = ImmutableField(classType, "S", "[Ljava/lang/String;", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value or AccessFlags.FINAL.value, null, ImmutableSet.of(), ImmutableSet.of())
        val clinit = MutableMethodImplementation(3)
        val size = encStrings.size
        if (size <= 7) clinit.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, size)) else clinit.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 0, size))
        clinit.addInstruction(BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0, ImmutableTypeReference("[Ljava/lang/String;")))
        encStrings.forEachIndexed { i, s -> clinit.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference(s))); if (i <= 7) clinit.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 2, i)) else clinit.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 2, i)); clinit.addInstruction(BuilderInstruction23x(Opcode.APUT_OBJECT, 0, 1, 2)) }
        clinit.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, arrayField)); clinit.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
        val get = MutableMethodImplementation(3)
        get.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, arrayField)); get.addInstruction(BuilderInstruction23x(Opcode.AGET_OBJECT, 1, 0, 2))
        get.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, ImmutableMethodReference("Lcom/secure/Decryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")))
        get.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); get.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 0))
        return ImmutableClassDef(classType, AccessFlags.PUBLIC.value, "Ljava/lang/Object;", emptyList(), null, ImmutableSet.of(), listOf(arrayField), emptyList(), listOf(ImmutableMethod(classType, "<clinit>", emptyList(), "V", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value, ImmutableSet.of(), ImmutableSet.of(), clinit), ImmutableMethod(classType, "get", listOf(ImmutableMethodParameter("I", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), get)), emptyList())
    }

    private fun buildDecryptorClass(): ClassDef {
        val ct = "Lcom/secure/Decryptor;"
        val kf = ImmutableField(ct, "key", "[B", AccessFlags.PRIVATE.value or AccessFlags.STATIC.value, null, ImmutableSet.of(), ImmutableSet.of())
        val ci = MutableMethodImplementation(2)
        ci.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("MySecureKey12345")))
        ci.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "getBytes", emptyList(), "[B")))
        ci.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1)); ci.addInstruction(BuilderInstruction21c(Opcode.SPUT_OBJECT, 1, kf)); ci.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
        val di = MutableMethodImplementation(5)
        di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 4, 0, 0, 0, 0, ImmutableMethodReference("Landroid/util/Base64;", "decode", listOf("Ljava/lang/String;", "I"), "[B")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1)); di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljavax/crypto/spec/SecretKeySpec;"))); di.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 0, kf))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 3, ImmutableStringReference("AES"))); di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 2, 0, 3, 0, 0, ImmutableMethodReference("Ljavax/crypto/spec/SecretKeySpec;", "<init>", listOf("[B", "Ljava/lang/String;"), "V")))
        di.addInstruction(BuilderInstruction21c(Opcode.CONST_STRING, 0, ImmutableStringReference("AES/ECB/PKCS5Padding"))); di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "getInstance", listOf("Ljava/lang/String;"), "Ljavax/crypto/Cipher;")))
        di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); di.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 3, 2)); di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 3, 2, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "init", listOf("I", "Ljava/security/Key;"), "V")))
        di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 1, 0, 0, 0, ImmutableMethodReference("Ljavax/crypto/Cipher;", "doFinal", listOf("[B"), "[B"))); di.addInstruction(BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1))
        di.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Ljava/lang/String;"))); di.addInstruction(BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 2, 1, 0, 0, 0, ImmutableMethodReference("Ljava/lang/String;", "<init>", listOf("[B"), "V"))); di.addInstruction(BuilderInstruction11x(Opcode.RETURN_OBJECT, 2))
        return ImmutableClassDef(ct, AccessFlags.PUBLIC.value, "Ljava/lang/Object;", emptyList(), null, ImmutableSet.of(), listOf(kf), emptyList(), listOf(ImmutableMethod(ct, "<clinit>", emptyList(), "V", AccessFlags.STATIC.value or AccessFlags.CONSTRUCTOR.value, ImmutableSet.of(), ImmutableSet.of(), ci), ImmutableMethod(ct, "decrypt", listOf(ImmutableMethodParameter("Ljava/lang/String;", ImmutableSet.of(), null)), "Ljava/lang/String;", AccessFlags.PUBLIC.value or AccessFlags.STATIC.value, ImmutableSet.of(), ImmutableSet.of(), di)), emptyList())
    }

    private fun createDexRewriter(mode: String, stringIndexMap: Map<String, Int>): DexRewriter {
        return DexRewriter(object : RewriterModule() {
            override fun getClassDefRewriter(rewriters: Rewriters): Rewriter<ClassDef> {
                val r = super.getClassDefRewriter(rewriters)
                return Rewriter { c -> if (c.type == "Lcom/secure/Decryptor;" || c.type == "Lcom/secure/StringPool;") c else r.rewrite(c) }
            }
            override fun getMethodImplementationRewriter(rewriters: Rewriters): Rewriter<MethodImplementation> {
                return Rewriter { impl ->
                    val m = MutableMethodImplementation(impl); val ins = m.instructions; var i = 0
                    while (i < ins.size) {
                        val inst = ins[i]
                        if (inst is ReferenceInstruction && inst.reference is StringReference) {
                            if (i + 1 < ins.size) { val n = ins[i + 1]; if (n is ReferenceInstruction && n.reference is ImmutableMethodReference) { val r = n.reference as ImmutableMethodReference; if (r.definingClass == "Lcom/secure/Decryptor;" && r.name == "decrypt") { i++; continue } } }
                            val str = (inst.reference as StringReference).string; val reg = if (inst is OneRegisterInstruction) inst.registerA else -1
                            if (reg >= 0) {
                                if (mode == "advanced" && stringIndexMap.containsKey(str)) {
                                    val idx = stringIndexMap[str]!!
                                    if (idx in -8..7) m.replaceInstruction(i, BuilderInstruction11n(Opcode.CONST_4, reg, idx)) else if (idx in Short.MIN_VALUE..Short.MAX_VALUE) m.replaceInstruction(i, BuilderInstruction21s(Opcode.CONST_16, reg, idx)) else m.replaceInstruction(i, BuilderInstruction31i(Opcode.CONST, reg, idx))
                                    val ref = ImmutableMethodReference("Lcom/secure/StringPool;", "get", listOf("I"), "Ljava/lang/String;")
                                    if (reg < 16) m.addInstruction(i + 1, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, ref)) else m.addInstruction(i + 1, BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, reg, 1, ref))
                                    m.addInstruction(i + 2, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg)); i += 2
                                } else {
                                    val enc = try { val c = Cipher.getInstance("AES/ECB/PKCS5Padding"); c.init(Cipher.ENCRYPT_MODE, encryptKey); Base64.encodeToString(c.doFinal(str.toByteArray()), Base64.NO_WRAP) } catch (e: Exception) { str }
                                    m.replaceInstruction(i, BuilderInstruction21c(Opcode.CONST_STRING, reg, ImmutableStringReference(enc)))
                                    val ref = ImmutableMethodReference("Lcom/secure/Decryptor;", "decrypt", listOf("Ljava/lang/String;"), "Ljava/lang/String;")
                                    if (reg < 16) m.addInstruction(i + 1, BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, reg, 0, 0, 0, 0, ref)) else m.addInstruction(i + 1, BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, reg, 1, ref))
                                    m.addInstruction(i + 2, BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg)); i += 2
                                }
                            }
                        }
                        i++
                    }
                    m
                }
            }
        })
    }

    private fun repackApk(originalApk: File, modifiedDexMap: Map<String, ByteArray>, outputApk: File) {
        ZipOutputStream(FileOutputStream(outputApk)).use { zos ->
            ZipFile(originalApk).use { zip -> val entries = zip.entries(); while (entries.hasMoreElements()) { val e = entries.nextElement(); if (!modifiedDexMap.containsKey(e.name)) { zos.putNextEntry(ZipEntry(e.name)); zip.getInputStream(e).use { it.copyTo(zos) }; zos.closeEntry() } } }
            for ((name, bytes) in modifiedDexMap) { zos.putNextEntry(ZipEntry(name)); zos.write(bytes); zos.closeEntry() }
        }
    }

    private fun appendLog(msg: String) { handler.post { tvLog.append("$msg\n") } }
}
