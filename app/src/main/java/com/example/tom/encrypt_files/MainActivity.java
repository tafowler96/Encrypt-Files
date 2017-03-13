package com.example.tom.encrypt_files;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.jcajce.provider.symmetric.AES;
import org.spongycastle.util.Integers;
import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static com.example.tom.encrypt_files.R.id.file_list;

public class MainActivity extends AppCompatActivity {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final String dirPath = "/storage/emulated/0/Download";
        File dir = new File(dirPath);

        File[] filelist = dir.listFiles();

        String[] fileNames = new String[filelist.length];
        for (int i = 0; i < fileNames.length; i++) {
            fileNames[i] = filelist[i].getName();
        }

        final ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, fileNames);
        ListView filesView = (ListView) findViewById(file_list);
        filesView.setAdapter(adapter);

        byte[] K;
        try {
            K = hashPassword("a");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        filesView.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                String item = ((TextView)view).getText().toString();
                byte[] K = new byte[0];
                try {
                    K = hashPassword("a");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                File inputFile, outputFile;
                String path = dirPath + "/" + item;
                if (item.endsWith(".enc")) {
                    inputFile = new File(path);
                    outputFile = new File(path.split(".enc")[0]);
                    try {
                        cryptFile(Cipher.DECRYPT_MODE, K, inputFile, outputFile);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                else {
                    inputFile = new File(path);
                    outputFile = new File(path + ".enc");
                    try {
                        cryptFile(Cipher.ENCRYPT_MODE, K, inputFile, outputFile);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                finish();
                startActivity(getIntent());
            }
        });

//        File inputFile = new File(dirPath + "/A.enc");
//        File outputFile = new File(dirPath + "/A.pdf");
//        try {
//            cryptFile(Cipher.DECRYPT_MODE, K, inputFile, outputFile);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    /**
     * Digests password using SHA-256
     * @param password input
     * @return array of output bytes
     * @throws NoSuchAlgorithmException
     */
    private byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());
        return md.digest();
    }

    /**
     * Performs AES-GCM encryption or decryption
     * @param cipherMode Encrypt or decrypt
     * @param key key for encryption
     * @param inputFile file to encrypt/decrypt
     * @param outputFile file to output to
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private void cryptFile(int cipherMode, byte[] key, File inputFile, File outputFile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException {
        byte[] N = Hex.decode("cafebabefacedbaddecaf888");
        Key k = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(N));
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(outputBytes);

        inputFile.delete();
        inputStream.close();
        outputStream.close();
    }
}
