#include "jni.h"
#include "stdio.h"
#include "JavaToC.h"
JNIEXPORT void JNICALL Java_JavaToC_helloC(JNIEnv *env, jobject javaobj) 
{
	printf("Hello World: From C");
	return;
}

JNIEXPORT void JNICALL Java_JavaToC_testC(JNIEnv *env, jobject javaobj) 
{
	printf("Hello World: From CS");
	return;
}

// cc HelloWorld.C -I C:/Progra~1/Java/jdk1.7.0_07/include -I C:/Progra~1/Java/jdk1.7.0_07/include/win32 -shared -o HelloWorld.dll