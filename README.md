https://blog.fireheart.in/a?ID=00800-6e612735-768c-46ff-803f-1ea82989bae4
Since Java is an interpreted language, before the class file is loaded by the JVM, it can be easily decompiled to get the source code. Compared with many methods provided on the Internet, such as using an obfuscator or a custom class loader, they are all based on the Java level and can also be decompiled. Finally, I finally found a more effective solution: using JVMTI to implement bytecode encryption of jar packages.

Introduction to JVMTI
JVMTI (JVM Tool Interface) is a native programming interface provided by the Java virtual machine, which can probe the internal state of the JVM and control the execution of the JVM application. Realizable functions include but are not limited to: debugging, monitoring, thread analysis, coverage analysis tools, etc.

Realization idea
JVMTI can monitor class loading events, so we can use a set of encryption algorithms to encrypt the bytecode of the jar package to be released, and then decrypt it before the JVM loads these classes. Since this part of the code will eventually be released in the form of a dynamic library (.dll, .so file), it is not easy to be cracked, so the source code can achieve a better protection effect.

Implementation steps
Open com_seaboat_bytecode_ByteCodeEncryptor.cpp, write specific encryption and decryption algorithms, and specify which classes need to be decrypted
```
#include <iostream>

#include "com_seaboat_bytecode_ByteCodeEncryptor.h"
#include "jni.h"
#include <jvmti.h>
#include <jni_md.h>


void encode(char *str)
{
	unsigned int m = strlen(str);
	for (int i = 0; i <m; i++)
	{
		//str[i] = ((str[i]-97)*k)-((str[i]-97)*k)/q*q + 97;
		str[i] = str[i] + 1;
	}

}

void decode(char *str)
{
	unsigned int m = strlen(str);
	//int k2 = (q + 1)/k;
	for (int i = 0; i <m; i++)
	{
		//str[i] = ((str[i]-97)*k2)-((str[i]-97)*k2)/q*q + 97;
		str[i] = str[i]-1;
	}
}


extern"C" JNIEXPORT jbyteArray JNICALL
Java_com_seaboat_bytecode_ByteCodeEncryptor_encrypt(JNIEnv * env, jclass cla, jbyteArray text)
{
	char* dst = (char*)env->GetByteArrayElements(text, 0);
	encode(dst);
	env->SetByteArrayRegion(text, 0, strlen(dst), (jbyte *)dst);
	return text;
}


void JNICALL ClassDecryptHook(
	jvmtiEnv *jvmti_env,
	JNIEnv* jni_env,
	jclass class_being_redefined,
	jobject loader,
	const char* name,
	jobject protection_domain,
	jint class_data_len,
	const unsigned char* class_data,
	jint* new_class_data_len,
	unsigned char** new_class_data
	)
{  
	*new_class_data_len = class_data_len;
	jvmti_env->Allocate(class_data_len, new_class_data);

	unsigned char* _data = *new_class_data;

   //Specify the class to be decrypted, here will decrypt all the classes under the cn.zzp package
	if (name&&strncmp(name, "cn/zzp/", 6) == 0) {

		for (int i = 0; i <class_data_len; i++)
		{
			_data[i] = class_data[i];
		}
		printf("%s\n","INFO: decode class.../n");
		decode((char*)_data);
	}
	else {
		for (int i = 0; i <class_data_len; i++)
		{
			_data[i] = class_data[i];
		}
	}

}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{

	jvmtiEnv *jvmti;
	//Create the JVM TI environment(jvmti)
	jint ret = vm->GetEnv((void **)&jvmti, JVMTI_VERSION);
	if (JNI_OK != ret)
	{
		printf("ERROR: Unable to access JVMTI!\n");
		return ret;
	}
	jvmtiCapabilities capabilities;
	(void)memset(&capabilities, 0, sizeof(capabilities));

	capabilities.can_generate_all_class_hook_events = 1;
	capabilities.can_tag_objects = 1;
	capabilities.can_generate_object_free_events = 1;
	capabilities.can_get_source_file_name = 1;
	capabilities.can_get_line_numbers = 1;
	capabilities.can_generate_vm_object_alloc_events = 1;

	jvmtiError error = jvmti->AddCapabilities(&capabilities);
	if (JVMTI_ERROR_NONE != error)
	{
		printf("ERROR: Unable to AddCapabilities JVMTI!\n");
		return error;
	}

	jvmtiEventCallbacks callbacks;
	(void)memset(&callbacks, 0, sizeof(callbacks));

	callbacks.ClassFileLoadHook = &ClassDecryptHook;
	error = jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
	if (JVMTI_ERROR_NONE != error) {
		printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
		return error;
	}

	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
	if (JVMTI_ERROR_NONE != error) {
		printf("ERROR: Unable to SetEventNotificationMode JVMTI!\n");
		return error;
	}

	return JNI_OK;
}
```
Compile and generate the dynamic library needed for encryption and decryption
```
cl/EHsc -LD com_seaboat_bytecode_ByteCodeEncryptor.cpp -FeByteCodeEncryptor.dll
```
Note: Here I used Visual Studio to complete the compilation, and an error was reported during the process: jvmti.h could not be found, enter the directory where jdk is located, and put the corresponding files in the bin/and bin/win32/directories into bin/include in the Visual Studio installation directory/To solve it.

Add the generated dynamic library file FeByteCodeEncryptor.dll to the system environment variables, sometimes you need to restart the system to take effect.

Use Java to encrypt the jar package to be released to get the encrypted jar package helloworld_encrypted.jar
```
package com.seaboat.bytecode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

public class ByteCodeEncryptor {
//Load the library (com_seaboat_bytecode_ByteCodeEncryptor.cpp), register the local method to the JVM
  static{
    System.loadLibrary("ByteCodeEncryptor");
  }
  
  public native static byte[] encrypt(byte[] text);//Indicates that the specific implementation of this method is in the native method

  public static void main(String[] args){
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buf = new byte[1024];
      String fileName = "D:\\jarpath\\helloworld.jar";

      File srcFile = new File(fileName);
      File dstFile = new File(fileName.substring(0, fileName.indexOf("."))+"_encrypted.jar");
      FileOutputStream dstFos = new FileOutputStream(dstFile);
      JarOutputStream dstJar = new JarOutputStream(dstFos);
      JarFile srcJar = new JarFile(srcFile);
      for (Enumeration<JarEntry> enumeration = srcJar.entries(); enumeration.hasMoreElements();) {
        JarEntry entry = enumeration.nextElement();
        InputStream is = srcJar.getInputStream(entry);
        int len;
        while ((len = is.read(buf, 0, buf.length)) != -1) {
          baos.write(buf, 0, len);
        }
        byte[] bytes = baos.toByteArray();
        String name = entry.getName();
        if(name.startsWith("cn/zzp/")){//Encrypt all class files under the cn.zzp package
          try {
            bytes = ByteCodeEncryptor.encrypt(bytes);
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
        JarEntry ne = new JarEntry(name);
        dstJar.putNextEntry(ne);
        dstJar.write(bytes);
        baos.reset();
      }
      srcJar.close();
      dstJar.close();
      dstFos.close();
      System.out.println("encrypt finished");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
```
To run the jar package, you need to specify the dependent dynamic library and the entry of the jar package (the class where the main method is located)
```
java -agentlib:ByteCodeEncryptor -cp helloworld_encrypted.jar cn.zzp.HelloWorld
```
Final effect
