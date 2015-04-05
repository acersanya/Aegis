package aegis;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
/**
 *
 * @author Александр
 */
public class Aegis {

    
  static short[] c = {0x01,0x02,0x03,0x05,0x08,0x0d,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62,0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd};
    
    
    
    public static short[][] paddByteArray(short[] array){
        short[] ar;
        int length = array.length;
       if(length%16!=0){
           ar = new short[length+(16-length%16)];
            System.arraycopy(array, 0, ar, 0, array.length);
           for(int i = array.length-1; i < ar.length; i++){
               ar[i] = 0;
           }
             return createMessages(ar);
           }
       
       return createMessages(array);
    }
/**
 * message divide length/16
 * @return 
 */
    public static short[][] createMessages(short[] ar) {
        short[][] result;
        result = new short[ar.length/16][2];
        int k = 0;
        for(int i = 0; i < result.length; i++){
            for(int j = 0; j < result[i].length; j++){
                result[i][j]= ar[k];
                k++;
            }
        }
        return result;
    }
    
    /**
     * IV vector
     */
    public static short[] generateIV (){
        short[] arrayIV = new short[16];
        Random r =  new Random();
        for(int i=0; i < arrayIV.length; i++){
            arrayIV[i] = (short)r.nextInt();
        }
        return arrayIV;
    }
    
    /*
    Key generator  from string 128 bit key using SHA-1
    */
    public static short[] generateKey(String keyPhrase) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] key = (keyPhrase).getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        short[] temp = new short[key.length];
        for (int i = 0; i < key.length; i++) {
            temp[i] = key[i];
        }
        return temp;
    }
    
    public static short[] xor(short[] a, short[] b) {
        short[] result = new short[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (short) (( a[i]) ^ ( b[i]));
        }

        return result;
    }
    
    /**
     * 
     * @param key - input key (16 byte length)
     * @param Message  - input message - mi (16 byte length)
     */
    public static void initializationAegis(short[] key, short[] Message,short[] IV){
        short[][] S = new short[5][16];
        S[0] = xor(key, Message);
        
        for(int i=16;i<c.length-1;i++){
            S[1][i] = c[i];
        }
        for(int i=0;i<16;i++){
            S[2][i]= c[i];
        }
        
        S[3] = xor(key,S[2]);
        S[4] = xor(key,S[1]);
        
       short[][] M = new short[10][128];
       for(int i = 4; i >= 0;i++){
           M[i+6] = key;
           M[i+1+5] = xor(key, IV);
       }
        
        
    }
    
    
    

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        Path path = Paths.get("D:\\info.txt");
        byte[] d = Files.readAllBytes(path);
        short[] data = new short[d.length];
        for (int i = 0; i < d.length; i++) {
            data[i] = d[i];
        }

        short[][] a = paddByteArray(data);
        short[] key = generateKey("hello");
        System.out.println(key.length);

    }
}