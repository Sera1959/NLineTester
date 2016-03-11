public class MD5Crypt {

  private static final String SALTCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  private static  final String B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  private static String toBase64(long v, int size) {
    StringBuffer result = new StringBuffer();

    while(--size >= 0) {
      result.append(B64.charAt((int)(v & 0x3f)));
      v >>>= 6;
    }

    return result.toString();
  }

  private static void clearBits(byte bits[]) {
    for(int i = 0; i < bits.length; i++) {
      bits[i] = 0;
    }
  }

  private static int unsignExtend(byte b) {
    return (int)b & 0xff;
  }

  public static String crypt(String password) {
    StringBuffer salt = new StringBuffer();
    java.util.Random randgen = new java.util.Random();

    while(salt.length() < 8) {
      int index = (int)(randgen.nextFloat() * SALTCHARS.length());
      salt.append(SALTCHARS.substring(index, index + 1));
    }

    return MD5Crypt.crypt(password, salt.toString());
  }

  public static String crypt(String password, String salt) {
    return MD5Crypt.crypt(password, salt, "$1$");
  }

  public static String apacheCrypt(String password) {
    StringBuffer salt = new StringBuffer();
    java.util.Random randgen = new java.util.Random();

    while(salt.length() < 8) {
      int index = (int)(randgen.nextFloat() * SALTCHARS.length());
      salt.append(SALTCHARS.substring(index, index + 1));
    }

    return MD5Crypt.apacheCrypt(password, salt.toString());
  }

  public static String apacheCrypt(String password, String salt) {
    return MD5Crypt.crypt(password, salt, "$apr1$");
  }

  public static String crypt(String password, String salt, String magic) {

    byte finalState[];
    MD5 ctx, ctx1;
    long l;

    if(salt.startsWith(magic)) salt = salt.substring(magic.length());
    if(salt.indexOf('$') != -1) salt = salt.substring(0, salt.indexOf('$'));
    if(salt.length() > 8) salt = salt.substring(0, 8);

    ctx = new MD5();

    ctx.update(password);
    ctx.update(magic);
    ctx.update(salt);

    ctx1 = new MD5();
    ctx1.update(password);
    ctx1.update(salt);
    ctx1.update(password);
    finalState = ctx1.finalState();

    for(int pl = password.length(); pl > 0; pl -= 16) {
      ctx.update(finalState, pl > 16?16:pl);
    }
    clearBits(finalState);

    for(int i = password.length(); i != 0; i >>>= 1) {
      if((i & 1) != 0) {
        ctx.update(finalState, 1);
      } else {
        ctx.update(password.getBytes(), 1);
      }
    }
    finalState = ctx.finalState();

    for(int i = 0; i < 1000; i++) {
      ctx1 = new MD5();

      if((i & 1) != 0) {
        ctx1.update(password);
      } else {
        ctx1.update(finalState, 16);
      }
      if((i % 3) != 0) ctx1.update(salt);
      if((i % 7) != 0) ctx1.update(password);
      if((i & 1) != 0) {
        ctx1.update(finalState, 16);
      } else {
        ctx1.update(password);
      }

      finalState = ctx1.finalState();
    }

    StringBuffer result = new StringBuffer();

    result.append(magic);
    result.append(salt);
    result.append("$");

    l = (unsignExtend(finalState[0]) << 16) | (unsignExtend(finalState[6]) << 8) | unsignExtend(finalState[12]);
    result.append(toBase64(l, 4));
    l = (unsignExtend(finalState[1]) << 16) | (unsignExtend(finalState[7]) << 8) | unsignExtend(finalState[13]);
    result.append(toBase64(l, 4));
    l = (unsignExtend(finalState[2]) << 16) | (unsignExtend(finalState[8]) << 8) | unsignExtend(finalState[14]);
    result.append(toBase64(l, 4));
    l = (unsignExtend(finalState[3]) << 16) | (unsignExtend(finalState[9]) << 8) | unsignExtend(finalState[15]);
    result.append(toBase64(l, 4));
    l = (unsignExtend(finalState[4]) << 16) | (unsignExtend(finalState[10]) << 8) | unsignExtend(finalState[5]);
    result.append(toBase64(l, 4));
    l = unsignExtend(finalState[11]);
    result.append(toBase64(l, 2));

    clearBits(finalState);

    return result.toString();
  }


}

