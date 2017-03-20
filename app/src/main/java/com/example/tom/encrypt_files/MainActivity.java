package com.example.tom.encrypt_files;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

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
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {
    ListView filesView;
    final private int READ_STORAGE_REQUEST = 1;
    final private int WRITE_STORAGE_REQUEST = 2;
    String dirPath = Environment.getExternalStorageDirectory().getPath();
    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        final Context context = this;
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        checkPermissions();
    }

    /**
     * Lists files to be encrypted
     */
    private void populateFiles() {
        filesView = (ListView) findViewById(R.id.file_list);

        String[] fileNames = listFiles(dirPath);

        final ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, fileNames);
        filesView.setAdapter(adapter);

        filesView.setOnItemClickListener(new android.widget.AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                final String item = ((TextView)view).getText().toString();
                // get prompts.xml view
                LayoutInflater li = LayoutInflater.from(getApplicationContext());
                View promptsView = li.inflate(R.layout.password_prompt, null);
                AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                        MainActivity.this);

                // set prompts.xml to alertdialog builder
                alertDialogBuilder.setView(promptsView);

                final EditText userInput = (EditText) promptsView
                        .findViewById(R.id.editTextDialogUserInput);

                userInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
                // set dialog message
                alertDialogBuilder
                        .setCancelable(false)
                        .setPositiveButton("OK",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog,int id) {
                                        String password = userInput.getText().toString();
                                        byte[] K = null;
                                        try {
                                            K = hashPassword(password);
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
                                        populateFiles();
                                    }
                                })
                        .setNegativeButton("Cancel",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog,int id) {
                                        dialog.cancel();
                                    }
                                });

                // create alert dialog
                AlertDialog alertDialog = alertDialogBuilder.create();

                // show it
                alertDialog.show();
            }
        });
    }

    /**
     * @param dirPath
     * @return array of filenames on device
     */
    private String[] listFiles(String dirPath) {
        File dir = new File(dirPath);
        File[] filelist = dir.listFiles();
        String[] fileNames = new String[filelist.length];
        for (int i = 0; i < fileNames.length; i++) {
            fileNames[i] = filelist[i].getName();
        }
    return fileNames;
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
    private void cryptFile(int cipherMode, byte[] key, File inputFile, File outputFile)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, IOException, BadPaddingException, IllegalBlockSizeException {
        FileInputStream inputStream = new FileInputStream(inputFile);
        int length = (int) inputFile.length();
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);
        Key k = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        if (cipherMode == Cipher.ENCRYPT_MODE) {
            byte[] iv = generateIV();
            cipher.init(cipherMode, k, new IvParameterSpec(iv));
            byte[] outputBytes = cipher.doFinal(inputBytes);
            byte[] byteFinal = new byte[outputBytes.length + iv.length];
            System.arraycopy(outputBytes, 0, byteFinal, 0, outputBytes.length);
            System.arraycopy(iv, 0, byteFinal, outputBytes.length, iv.length);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(byteFinal);
            outputStream.close();

        } else {
            byte[] iv = new byte[32];
            int startIndex = (int) inputFile.length() - 32;
            for(int i = startIndex; i < length; i++) {
                iv[i - startIndex] = inputBytes[i];

            }

            cipher.init(cipherMode, k, new IvParameterSpec(iv));
            byte[] byteFinal = new byte[inputBytes.length - iv.length];
            System.arraycopy(inputBytes, 0, byteFinal, 0, byteFinal.length);
            byte[] outputBytes = cipher.doFinal(byteFinal);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
            outputStream.close();

        }
        inputFile.delete();
        inputStream.close();

    }

    /**
     * @return generated initialization vector
     */
    private byte[] generateIV() {
        byte[] iv = new byte[32];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Requests permission if necessary
     */
    private void checkPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED ||
                ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, READ_STORAGE_REQUEST);
        }
        else {
            populateFiles();
        }
    }

    /**
     * Closes app if permission isn't granted
     * @param requestCode
     * @param permissions
     * @param grantResults
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        switch(requestCode) {
            case READ_STORAGE_REQUEST: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    populateFiles();
                }
                else {
                    finish();
                }
                return;
            }
            case WRITE_STORAGE_REQUEST: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    populateFiles();
                }
                else {
                    finish();
                }
                return;
            }
        }
    }
}