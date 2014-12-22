
import re

def convertFunc(fromdirname, filename, s):
    s = s.replace("fe t0;", "fe t0 = new int[10];")
    s = s.replace("fe t1;", "fe t1 = new int[10];")
    s = s.replace("fe t2;", "fe t2 = new int[10];")
    s = s.replace("fe t3;", "fe t3 = new int[10];")

    s = s.replace("fe u;", "fe u = new int[10];") # ge_frombytes
    s = s.replace("fe v;", "fe v = new int[10];") # ge_frombytes
    s = s.replace("fe vxx;", "fe vxx = new int[10];") # ge_frombytes
    s = s.replace("fe check;", "fe check = new int[10];") # ge_frombytes
    s = s.replace("fe recip;", "fe recip = new int[10];") # ge_tobytes
    s = s.replace("fe x;", "fe x = new int[10];") # ge_tobytes
    s = s.replace("fe y;", "fe y = new int[10];") # ge_tobytes

    s = s.replace("ge_p1p1 *", "ge_p1p1 ")
    s = s.replace("ge_p2 *", "ge_p2 ")
    s = s.replace("ge_p3 *", "ge_p3 ")
    s = s.replace("ge_precomp *", "ge_precomp ")
    s = s.replace("ge_cached *", "ge_cached ")
    s = s.replace("extern ", "")
    s = s.replace("ge_p2 q;", "ge_p2 q = new ge_p2();")
    s = s.replace("unsigned char s[32]", "byte[] s = new byte[32]")
    #ge_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
    s = s.replace("ge_p1p1 t;", "ge_p1p1 t = new ge_p1p1();")
    s = s.replace("ge_p3 u;", "ge_p3 u = new ge_p3();")
    s = s.replace("ge_p3 A2;", "ge_p3 A2 = new ge_p3();")
    s = s.replace("signed char aslide[256];", "byte[] aslide = new byte[256];")
    s = s.replace("signed char bslide[256];", "byte[] bslide = new byte[256];")

    s = s.replace("static const unsigned char zero[32];", "static final byte[] zero = new byte[32];")
    s = s.replace("fe ", "int[] ")
    s = s.replace("const ", "")
    s = s.replace("crypto_int32", "int")
    s = s.replace("crypto_int64", "long")
    s = s.replace("crypto_uint64", "long") # weird but I think ok - fe_frombytes
    s = s.replace("unsigned char *", "byte[] ")
    s = s.replace("signed char *", "byte[] ") # for ge_double_scalarmult, has to be after prev line

    s = s.replace("unsigned int", "int") # fe_cmov
    s = s.replace("unsigned char", "int") # fe_cmov
    
    s = s.replace("void", "public static void")
    s = s.replace("static long", "public static long") # fe_frombytes
    s = s.replace("int fe", "public static int fe") # fe_isnegative

    for includeFile in ("pow225521", "pow22523", "ge_add", "base2", "d2", "ge_sub", "d", "sqrtm1",
                        "ge_madd", "ge_msub", "ge_p2_dbl", "base"):
        includeIndex = s.find('#include "%s.h"' % includeFile)
        if includeIndex != -1:
            s2 = open(fromdirname + "/" + "%s.h" % includeFile).read()
            eolIndex = s.find("\n", includeIndex)
            s = s[ : eolIndex+1] + s2 + s[eolIndex+1 : ]

    if filename in ("fe_invert", "fe_isnegative", "fe_isnonzero", "fe_pow22523"):
        for funcToExpand in ["fe_tobytes", "fe_sq", "fe_mul", "crypto_verify_32"]:
            s = s.replace(funcToExpand, "%s.%s" % (funcToExpand, funcToExpand))

    if filename in ("ge_add", "ge_madd", "ge_msub", "ge_p1p1_to_p2", "ge_p1p1_to_p3",
                    "ge_p2_0", "ge_p2_dbl", "ge_p3_0", "ge_p3_dbl", "ge_p3_to_cached",
                    "ge_p3_to_p2", "ge_p3_tobytes", "ge_precomp_0", "ge_sub", "ge_tobytes",
                    "ge_double_scalarmult", "ge_p2_dbl", "ge_p3_dbl", "ge_scalarmult_base"):
        funcsToExpand = ["fe_add", "fe_sub", "fe_mul", "fe_copy", "ge_p3_to_p2", "ge_p2_dbl",
                         "fe_invert", "fe_tobytes", "fe_isnegative", "fe_0", "fe_1", 
                         "ge_p1p1_to_p3", "ge_madd", "ge_sub", "ge_msub", "ge_p3_to_cached",
                         "ge_add", "ge_p1p1_to_p2", "ge_p2_0", "ge_p3_dbl", "fe_sq", "fe_sq2",
                         "fe_cmov", "ge_precomp_0", "fe_neg", "ge_p3_0"]
        funcsToExpand = [f for f in funcsToExpand if f != filename]
        for funcToExpand in funcsToExpand:
            s = s.replace(funcToExpand+"(", "%s.%s(" % (funcToExpand, funcToExpand))

    for count in range(10): # fe_frombytes, mul, sq, sq2 (long->int)
        t1 = "h[%d] = h%d;" % (count, count)
        t2 = "h[%d] = (int)h%d;" % (count, count)
        s = s.replace(t1, t2)

    s = s.replace("->", ".")

    for ampchar in ("utABbmrqs"): #replace pointer-address-of in ge_
        s = s.replace("&"+ampchar, ampchar)

    s = s.replace("#include", "//CONVERT #include")
    s = "package javasrc;\n\npublic class %s {\n\n%s\n\n}\n" % (filename, s)
    return s

def convertFile(fromdirname, filename):
    s = open(fromdirname + "/" + filename+".c").read()
    return convertFunc(fromdirname, filename, s)

def convertFiles(fromdirname, todirname):
    filenames = [
        "fe_0",
        "fe_1",
        "fe_add",
        "fe_cmov",
        "fe_copy",
        "fe_frombytes",
        "fe_invert",
        "fe_isnegative",
        "fe_isnonzero",
        "fe_mul",
        "fe_neg",
        "fe_pow22523",
        "fe_sq",
        "fe_sq2",
        "fe_sub",
        "fe_tobytes",
        "ge_add",
        "ge_p1p1_to_p3",
        "ge_p3_to_p2",
        "ge_double_scalarmult",  
        "ge_p2_0",
        "ge_p3_tobytes",
        "ge_frombytes",
        "ge_p2_dbl",
        "ge_precomp_0",
        "ge_madd",
        "ge_p3_0",
        "ge_scalarmult_base",
        "ge_msub",
        "ge_p3_dbl",
        "ge_sub",
        "ge_p1p1_to_p2",
        "ge_p3_to_cached",
        "ge_tobytes"]
        
    for filename in filenames:
        s = convertFile(fromdirname, filename)
        #print(filename + "\n=======\n" + s)
        open(todirname + "/" + filename+".java", "w").write(s)

convertFiles("ref10_extract", "generated")

#import sys
#filename = sys.argv[1]
#print convertFile("ref10_extract", filename)

