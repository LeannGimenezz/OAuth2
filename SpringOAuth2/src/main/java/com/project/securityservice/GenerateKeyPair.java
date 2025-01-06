package com.project.securityservice;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GenerateKeyPair {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        // Generate a key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        var keyPair = keyPairGenerator.generateKeyPair();
        byte[] pub = keyPair.getPublic().getEncoded();
        byte[] priv = keyPair.getPrivate().getEncoded();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream("pum.pem")));
        PemObject pemObject = new PemObject("PUBLIC KEY", pub);
        pemWriter.writeObject(pemObject);
        pemWriter.close();

        PemWriter pemWriter2 = new PemWriter(new OutputStreamWriter(new FileOutputStream("pri.pem")));
        PemObject pemObject2 = new PemObject("PRIVATE KEY", priv);
        pemWriter2.writeObject(pemObject2);
        pemWriter2.close();
    }
}
