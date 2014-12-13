
import re

def convertFunc(fromdirname, filename, s):
    s = s.replace("unsigned char s[32]", "byte[] s = new byte[32]")
    s = s.replace("static const unsigned char zero[32];", "static final byte[] zero = new byte[32];")
    s = s.replace("fe ", "int[] ")
    s = s.replace("const ", "")
    s = s.replace("crypto_int32", "int")
    s = s.replace("crypto_int64", "long")
    s = s.replace("crypto_uint64", "long") # weird but I think ok - fe_frombytes
    s = s.replace("unsigned char *", "byte[] ")

    s = s.replace("unsigned int", "int") # fe_cmov
    s = s.replace("unsigned char", "int") # fe_cmov
    
    s = s.replace("void", "public static void")
    s = s.replace("static long", "public static long") # fe_frombytes
    s = s.replace("int fe", "public static int fe") # fe_isnegative

    includeIndex = s.find('#include "pow225521.h"')
    if includeIndex != -1:
        s2 = open(fromdirname + "/" + "pow225521.h").read()
        eolIndex = s.find("\n", includeIndex)
        s = s[ : eolIndex+1] + s2 + s[eolIndex+1 : ]

    if filename in ("fe_invert", "fe_isnegative", "fe_isnonzero"):
        for funcToExpand in ["fe_tobytes", "fe_sq", "fe_mul"]:
            s = s.replace(funcToExpand, "%s.%s" % (funcToExpand, funcToExpand))

    s = s.replace("#include", "//CONVERT #include")
    s = "package generated;\n\npublic class %s {\n\n%s\n\n}\n" % (filename, s)
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
        "fe_tobytes"]
    for filename in filenames:
        s = convertFile(fromdirname, filename)
        #print(filename + "\n=======\n" + s)
        open(todirname + "/" + filename+".java", "w").write(s)

convertFiles("ref10_extract", "generated")

#import sys
#filename = sys.argv[1]
#print convertFile("ref10_extract", filename)

