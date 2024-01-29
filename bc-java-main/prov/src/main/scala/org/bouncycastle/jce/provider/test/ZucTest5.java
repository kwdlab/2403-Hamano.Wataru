package org.bouncycastle.jce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class ZucTest5
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

        AlgorithmParameters algParams = AlgorithmParameters.getInstance(pCipher.getAlgorithm(), "BC");
        
        algParams.init(new IvParameterSpec(myIV));
        
        pCipher.init(Cipher.DECRYPT_MODE, myKey, algParams);
        
        pCipher.doFinal(myData, 0, myData.length, myOutput, 0);
    }
    public void performTest()
        throws Exception
    {   
        final Cipher zuc128 = Cipher.getInstance("Zuc-128", "BC");

        long startTimeZuc128_0 = System.nanoTime();
        testCipher(zuc128, ZUC128_TEST1);
        long endTimeZuc128_0 = System.nanoTime();
        long executionTimeZuc128_0 = endTimeZuc128_0 - startTimeZuc128_0;
        System.out.println("Zuc-128の処理時間: " + executionTimeZuc128_0 + " ナノ秒");

        long startTimeZuc128 = System.nanoTime();
        for(int i = 0; i <= 9; i++){
            testCipher(zuc128, ZUC128_TEST1);
        }
        long endTimeZuc128 = System.nanoTime();
        long executionTimeZuc128 = endTimeZuc128 - startTimeZuc128;
        System.out.println("Zuc-128Test1の処理時間: " + executionTimeZuc128 + " ナノ秒");

        long startTimeZuc128_2 = System.nanoTime();
        for(int i = 0; i <= 9; i++){
            testCipher(zuc128, ZUC128_TEST2);
        }
        long endTimeZuc128_2 = System.nanoTime();
        long executionTimeZuc128_2 = endTimeZuc128_2 - startTimeZuc128_2;
        System.out.println("Zuc-128Test2の処理時間: " + executionTimeZuc128_2 + " ナノ秒");

        final Cipher zuc256 = Cipher.getInstance("Zuc-256", "BC");
        long startTimeZuc256 = System.nanoTime();
        for(int i = 0; i <= 9; i++){
            testCipher(zuc256, ZUC256_TEST1);
        }
        long endTimeZuc256 = System.nanoTime();
        long executionTimeZuc256 = endTimeZuc256 - startTimeZuc256;
        System.out.println("Zuc-256Test1の処理時間: " + executionTimeZuc256 + " ナノ秒");
        
        long startTimeZuc256_2 = System.nanoTime();
        for(int i = 0; i <= 9; i++){
            testCipher(zuc256, ZUC256_TEST2);
        }
        long endTimeZuc256_2 = System.nanoTime();
        long executionTimeZuc256_2 = endTimeZuc256_2 - startTimeZuc256_2;
        System.out.println("Zuc-256Test2の処理時間: " + executionTimeZuc256_2 + " ナノ秒");
        
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

        Test test = new ZucTest5();

        TestResult result = test.perform();

        System.out.println(result.toString());
        if (result.getException() != null)
        {
            result.getException().printStackTrace();
        }
    }
}
