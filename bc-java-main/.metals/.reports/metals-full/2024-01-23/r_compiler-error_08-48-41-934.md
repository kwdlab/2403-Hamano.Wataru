file:///C:/Users/hamano/Documents/college/zemi/github/bc-java-main/prov/src/test/java/org/bouncycastle/jce/provider/test/ZucTest4.java
### java.util.NoSuchElementException: next on empty iterator

occurred in the presentation compiler.

action parameters:
uri: file:///C:/Users/hamano/Documents/college/zemi/github/bc-java-main/prov/src/test/java/org/bouncycastle/jce/provider/test/ZucTest4.java
text:
```scala
package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ZucTest4
    extends SimpleTest
{
    private static final String KEY128_1 =
        "00000000000000000000000000000000";
    private static final String KEY128_2 =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private static final String KEY256_1 =
        "00000000000000000000000000000000" +
            "00000000000000000000000000000000";
    private static final String KEY256_2 =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    private static final String IV128_1 = "00000000000000000000000000000000";
    private static final String IV128_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    private static final String IV200_1 = "00000000000000000000000000000000000000000000000000";
    private static final String IV200_2 = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3F3F3F3F3F3F3F3F";
    
    //バイト数は上下0.3秒ぐらいの誤差、初起動時の大差がある330メガバイト
    private char[] initializationChars = new char[1024*1024*165];
    private static char[] initializeChars(char[] chars) {
        for (int i = 0; i < chars.length; ++i) {
            chars[i] = '0';
        }
        return chars;
    }
    private String initialString = new String(initializeChars(initializationChars));




    private final TestCase ZUC128_TEST1 = new TestCase(KEY128_1, IV128_1,
        initialString
    );
    private final TestCase ZUC128_TEST2 = new TestCase(KEY128_2, IV128_2,
        initialString
    );
    private final TestCase ZUC256_TEST1 = new TestCase(KEY256_1, IV200_1,
        initialString
    );
    private final TestCase ZUC256_TEST2 = new TestCase(KEY256_2, IV200_2,
        initialString
    );

    private final TestCase MAC128_TEST1 = new TestCase(KEY128_1, IV128_1, "508dd5ff");
    private final TestCase MAC128_TEST2 = new TestCase(KEY128_1, IV128_1, "fbed4c12");
    private final TestCase MAC256_TEST1 = new TestCase(KEY256_1, IV200_1, "d85e54bbcb9600967084c952a1654b26");
    private final TestCase MAC256_TEST2 = new TestCase(KEY256_1, IV200_1, "df1e8307b31cc62beca1ac6f8190c22f");
    private final TestCase MAC256_64_TEST1 = new TestCase(KEY256_1, IV200_1, "673e54990034d38c");
    private final TestCase MAC256_64_TEST2 = new TestCase(KEY256_1, IV200_1, "130dc225e72240cc");
    private final TestCase MAC256_32_TEST1 = new TestCase(KEY256_1, IV200_1, "9b972a74");
    private final TestCase MAC256_32_TEST2 = new TestCase(KEY256_1, IV200_1, "8754f5cf");
    
    public String getName()
    {
        return "Zuc";
    }

    /**
     * Test the Cipher against the results.
     *
     * @param pCipher   the cipher to test.
     * @param pTestCase the testCase
     */
    void testCipher(final Cipher pCipher,
                    final TestCase pTestCase)
    throws Exception
    {





        /* Access the expected bytes */
        final byte[] myExpected = Hex.decode(pTestCase.theExpected);

        /* Create the output buffer */
        final byte[] myOutput = new byte[myExpected.length];
        
        /* Access plainText or nulls */
        final byte[] myData = pTestCase.thePlainText != null
            ? Hex.decode(pTestCase.thePlainText)
            : new byte[myExpected.length];

        /* Access the key and the iv */
        final SecretKey myKey = new SecretKeySpec(Hex.decode(pTestCase.theKey), pCipher.getAlgorithm());
        final byte[] myIV = Hex.decode(pTestCase.theIV);

        /* Initialise the cipher and create the keyStream */
        pCipher.init(Cipher.ENCRYPT_MODE, myKey, new IvParameterSpec(myIV));

        pCipher.doFinal(myData, 0, myData.length, myOutput, 0); 

        /*System.out.print("myExpected: ");
        for (byte b : myExpected) {
            System.out.print(b + " ");
        }
        System.out.println();

        System.out.print("myOutput: ");
        for (byte b : myOutput) {
            System.out.print(b + " ");
        }
        System.out.println();*/

        //初期ベクトルと鍵が同じであるならば出力結果は同じになるので出力結果を入力値にしているので変えると必ずエラーがでる
        //isTrue("Encryption mismatch", Arrays.areEqual(myExpected, myOutput));
        
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(pCipher.getAlgorithm(), "BC");
        
        algParams.init(new IvParameterSpec(myIV));
        
        pCipher.init(Cipher.DECRYPT_MODE, myKey, algParams);
        
        pCipher.doFinal(myData, 0, myData.length, myOutput, 0);
    }

    /**
     * Test the Mac against the results.
     *
     * @param pMac      the mac to test.
     * @param pOnes     use all ones as data?
     * @param pTestCase the testCase
     */
    void testMac(final Mac pMac,
                 final boolean pOnes,
                 final TestCase pTestCase)
        throws Exception
    {
        /* Access the expected bytes */
        final byte[] myExpected = Hex.decode(pTestCase.theExpected);

        /* Create the output buffer and the data */
        final byte[] myOutput = new byte[pMac.getMacLength()];

        //isTrue("Mac length mismatch", myExpected.length == myOutput.length);

        final byte[] myData = new byte[(pOnes ? 1024*1024*25 : 1024*1024*25 )];
        Arrays.fill(myData, (byte)(pOnes ? 0x11 : 0));

        /* Access the key and the iv */
        final SecretKey myKey = new SecretKeySpec(Hex.decode(pTestCase.theKey), pMac.getAlgorithm());
        final byte[] myIV = Hex.decode(pTestCase.theIV);

        /* Initialise the cipher and create the keyStream */
        pMac.init(myKey, new IvParameterSpec(myIV));
        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        /* Check the mac */
        //isTrue("Mac mismatch", Arrays.areEqual(myExpected, myOutput));

        /* Check doFinal reset */
        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        //isTrue("DoFinal Mac mismatch", Arrays.areEqual(myExpected, myOutput));

        /* Check reset() */
        pMac.update(myData, 0, myData.length);

        pMac.reset();

        pMac.update(myData, 0, myData.length);
        pMac.doFinal(myOutput, 0);

        //isTrue("Reset Mac mismatch", Arrays.areEqual(myExpected, myOutput));
    }

    private void simpleTest(Cipher zuc)
        throws Exception
    {
        //暗号化して複合化して元に戻るか調べる
        KeyGenerator kGen = KeyGenerator.getInstance(zuc.getAlgorithm(), "BC");
        byte[] msg = Strings.toByteArray("Hello, world!");
        SecretKey k = kGen.generateKey();

        zuc.init(Cipher.ENCRYPT_MODE, k);

        byte[] enc = zuc.doFinal(msg);

        byte[] iv = zuc.getIV();
        AlgorithmParameters algParam = zuc.getParameters();

        zuc.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));

        byte[] dec = zuc.doFinal(enc);

        areEqual(msg, dec);

        zuc.init(Cipher.DECRYPT_MODE, k, algParam);

        dec = zuc.doFinal(enc);

        areEqual(msg, dec);
    }





























    public void performTest()
        throws Exception
    {
        
        final Cipher zuc128 = Cipher.getInstance("Zuc-128", "BC");
        long startTimeZuc128 = System.nanoTime();
        testCipher(zuc128, ZUC128_TEST1);
        long endTimeZuc128 = System.nanoTime();
        long executionTimeZuc128 = endTimeZuc128 - startTimeZuc128;
        System.out.println("Zuc-128Test1の処理時間: " + executionTimeZuc128 + " ナノ秒");
        
        long startTimeZuc128_2 = System.nanoTime();
        testCipher(zuc128, ZUC128_TEST2);
        long endTimeZuc128_2 = System.nanoTime();
        long executionTimeZuc128_2 = endTimeZuc128_2 - startTimeZuc128_2;
        System.out.println("Zuc-128Test2の処理時間: " + executionTimeZuc128_2 + " ナノ秒");

        simpleTest(zuc128);

        final Cipher zuc256 = Cipher.getInstance("Zuc-256", "BC");
        long startTimeZuc256 = System.nanoTime();
        testCipher(zuc256, ZUC256_TEST1);
        long endTimeZuc256 = System.nanoTime();
        long executionTimeZuc256 = endTimeZuc256 - startTimeZuc256;
        System.out.println("Zuc-256Test1の処理時間: " + executionTimeZuc256 + " ナノ秒");
        
        long startTimeZuc256_2 = System.nanoTime();
        testCipher(zuc256, ZUC256_TEST2);
        long endTimeZuc256_2 = System.nanoTime();
        long executionTimeZuc256_2 = endTimeZuc256_2 - startTimeZuc256_2;
        System.out.println("Zuc-256Test2の処理時間: " + executionTimeZuc256_2 + " ナノ秒");
        

        simpleTest(zuc256);
        


       
        final Mac mac128 = Mac.getInstance("Zuc-128", "BC");
        // check reset
        mac128.reset();

        long startTimeMac128 = System.nanoTime();
        testMac(mac128, false, MAC128_TEST1);
        long endTimeMac128 = System.nanoTime();
        long executionTimeMac128 = endTimeMac128 - startTimeMac128;
        System.out.println("Zuc-128 false Macの処理時間: " + executionTimeMac128 + " ナノ秒");

        long startTimeMac128t = System.nanoTime();
        testMac(mac128, true, MAC128_TEST2);
        long endTimeMac128t = System.nanoTime();
        long executionTimeMac128t = endTimeMac128t - startTimeMac128t;
        System.out.println("Zuc-128 true Macの処理時間: " + executionTimeMac128t + " ナノ秒");
        
        
        
        final Mac mac256 = Mac.getInstance("Zuc-256", "BC");
        // check reset
        mac256.reset();
        long startTimeMac256 = System.nanoTime();
        testMac(mac256, false, MAC256_TEST1);
        long endTimeMac256 = System.nanoTime();
        long executionTimeMac256 = endTimeMac256 - startTimeMac256;
        System.out.println("Zuc-256 false Macの処理時間: " + executionTimeMac256 + " ナノ秒");
        
        long startTimeMac256t = System.nanoTime();
        testMac(mac256, true, MAC256_TEST2);
        long endTimeMac256t = System.nanoTime();
        long executionTimeMac256t = endTimeMac256t - startTimeMac256t;
        System.out.println("Zuc-256 true Macの処理時間: " + executionTimeMac256t + " ナノ秒");
        

        
        final Mac mac256_128 = Mac.getInstance("Zuc-256-128", "BC");
        
        long startTimeMac256_128 = System.nanoTime();
        testMac(mac256_128, false, MAC256_TEST1);
        long endTimeMac256_128 = System.nanoTime();
        long executionTimeMac256_128 = endTimeMac256_128  - startTimeMac256_128;
        System.out.println("mac256_128 false Macの処理時間: " + executionTimeMac256_128 + " ナノ秒");
        
        long startTimeMac256_128t = System.nanoTime();
        testMac(mac256_128, true, MAC256_TEST2);
        long endTimeMac256_128t = System.nanoTime();
        long executionTimeMac256_128t = endTimeMac256_128t  - startTimeMac256_128t;
        System.out.println("mac256_128 true Macの処理時間: " + executionTimeMac256_128t + " ナノ秒");
        testMac(mac256_128, true, MAC256_TEST2);

        final Mac mac256_64 = Mac.getInstance("Zuc-256-64", "BC");
        
        long startTimeMac256_64 = System.nanoTime();
        testMac(mac256_64, false, MAC256_64_TEST1);
        long endTimeMac256_64 = System.nanoTime();
        long executionTimeMac256_64 = endTimeMac256_64  - startTimeMac256_64;
        System.out.println("mac256_64 false Macの処理時間: " + executionTimeMac256_64 + " ナノ秒");
        
        long startTimeMac256_64t = System.nanoTime();
        testMac(mac256_64, true, MAC256_64_TEST2);
        long endTimeMac256_64t = System.nanoTime();
        long executionTimeMac256_64t = endTimeMac256_64t  - startTimeMac256_64t;
        System.out.println("mac256_64 true Macの処理時間: " + executionTimeMac256_64t + " ナノ秒");
        

        final Mac mac256_32 = Mac.getInstance("Zuc-256-32", "BC");

        long startTimeMac256_32 = System.nanoTime();
        testMac(mac256_32, false, MAC256_32_TEST1);
        long endTimeMac256_32 = System.nanoTime();
        long executionTimeMac256_32 = endTimeMac256_32  - startTimeMac256_32;
        System.out.println("mac256_32 false Macの処理時間: " + executionTimeMac256_32 + " ナノ秒");
        
        long startTimeMac256_32t = System.nanoTime();
        testMac(mac256_32, true, MAC256_32_TEST2);
        long endTimeMac256_32t = System.nanoTime();
        long executionTimeMac256_32t = endTimeMac256_32t  - startTimeMac256_32t;
        System.out.println("mac256_32 true Macの処理時間: " + executionTimeMac256_32t + " ナノ秒");
        
    }



















    /**
     * The TestCase.
     */
    private static class TestCase
    {
        /**
         * The testCase.
         */
        private final String theKey;
        private final String theIV;
        private final String thePlainText;
        private final String theExpected;

        /**
         * Constructor.
         *
         * @param pKey      the key
         * @param pIV       the IV
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pExpected)
        {
            this(pKey, pIV, null, pExpected);
        }

        /**
         * Constructor.
         *
         * @param pKey      the key
         * @param pIV       the IV
         * @param pPlain    the plainText
         * @param pExpected the expected results.
         */
        TestCase(final String pKey,
                 final String pIV,
                 final String pPlain,
                 final String pExpected)
        {
            theKey = pKey;
            theIV = pIV;
            thePlainText = pPlain;
            theExpected = pExpected;
        }
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test test = new ZucTest4();






        TestResult result = test.perform();

        System.out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}

```



#### Error stacktrace:

```
scala.collection.Iterator$$anon$19.next(Iterator.scala:973)
	scala.collection.Iterator$$anon$19.next(Iterator.scala:971)
	scala.collection.mutable.MutationTracker$CheckedIterator.next(MutationTracker.scala:76)
	scala.collection.IterableOps.head(Iterable.scala:222)
	scala.collection.IterableOps.head$(Iterable.scala:222)
	scala.collection.AbstractIterable.head(Iterable.scala:933)
	dotty.tools.dotc.interactive.InteractiveDriver.run(InteractiveDriver.scala:168)
	scala.meta.internal.pc.MetalsDriver.run(MetalsDriver.scala:45)
	scala.meta.internal.pc.PcCollector.<init>(PcCollector.scala:45)
	scala.meta.internal.pc.PcSemanticTokensProvider$Collector$.<init>(PcSemanticTokensProvider.scala:61)
	scala.meta.internal.pc.PcSemanticTokensProvider.Collector$lzyINIT1(PcSemanticTokensProvider.scala:61)
	scala.meta.internal.pc.PcSemanticTokensProvider.Collector(PcSemanticTokensProvider.scala:61)
	scala.meta.internal.pc.PcSemanticTokensProvider.provide(PcSemanticTokensProvider.scala:90)
	scala.meta.internal.pc.ScalaPresentationCompiler.semanticTokens$$anonfun$1(ScalaPresentationCompiler.scala:99)
```
#### Short summary: 

java.util.NoSuchElementException: next on empty iterator