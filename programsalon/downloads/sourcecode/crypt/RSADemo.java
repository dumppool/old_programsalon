/*
    A basic extension of the java.applet.Applet class
 */

import java.awt.*;
import java.applet.*;
import java.awt.event.*;
import java.math.*;
import java.util.*;

public class RSADemo extends Applet implements ActionListener{

    final int BLOCKSIZE = 12;
    boolean isEncrypted = false;
    boolean isSeted = false;

    BigInteger P, Q, N, E, D, T;
    BigInteger ZERO = new BigInteger("0");
    BigInteger ONE = new BigInteger("1");
    BigInteger ciphertext[] = new BigInteger[100];
    Random rand = new Random();

	public void init() {
		super.init();

        Font f = new Font("Helvetica", Font.BOLD, 14);
		setLayout(null);
		addNotify();
		resize(448,512);
		setBackground(new Color(15719830));
		ta_info = new TextArea();
		ta_info.setEditable(false);
		ta_info.setText("Welcome to RSA Demo Applet.\nBefore generating the pair of public key and private key,\nyou must choice the ODD e number, and then press SET button.\n\n");
		ta_info.setLocation(12,336);
		ta_info.setSize(420,160);
		add(ta_info);
		ta_msg = new TextArea();
		ta_msg.setLocation(12,168);
		ta_msg.setSize(420,132);
		ta_msg.setFont(f);
		add(ta_msg);
		tf_e = new TextField();
		tf_e.setLocation(24,36);
		tf_e.setSize(300,24);
		add(tf_e);
		but_set = new Button("Set");
		but_set.setLocation(348,36);
		but_set.setSize(84,24);
		but_set.addActionListener(this);
		add(but_set);
		but_reset = new Button("Reset");
		but_reset.setLocation(348,72);
		but_reset.setSize(84,60);
		but_reset.addActionListener(this);
		add(but_reset);
		but_e = new Button("Apply public key e to your message ...");
		but_e.setLocation(24,72);
		but_e.setSize(300,24);
		but_e.addActionListener(this);
		add(but_e);
		but_d = new Button("Apply private key d to your message ...");
		but_d.setLocation(24,108);
		but_d.setSize(300,24);
		but_d.addActionListener(this);
		add(but_d);
		label1 = new Label("Input the value of public key e:");
		label1.setLocation(14,12);
		label1.setSize(264,24);
		add(label1);
		label2 = new Label("Message:");
		label2.setLocation(12,144);
		label2.setSize(120,24);
		add(label2);
		label3 = new Label("Operation Information:");
		label3.setLocation(12,312);
		label3.setSize(144,24);
		add(label3);
		//{{INIT_CONTROLS
		//}}
	}

    public void actionPerformed(ActionEvent event) {
        
        Object src = event.getSource();
        if (src == but_set) {
            if (tf_e.getText().length() == 0) ta_info.append("WARNING: You must input the ODD e number first.\n");
            else {
                if (generatePQNTED(tf_e.getText())) {
                    ta_info.append("Congratulation! ...\nYou have generated the pair of public / private key.\n");
                    ta_info.append("p: "+P.toString()+"\n");
                    ta_info.append("q: "+Q.toString()+"\n");
                    ta_info.append("n: "+N.toString()+"\n");
                    ta_info.append("e: "+E.toString()+"\n");
                    ta_info.append("d: "+D.toString()+"\n");
                    ta_info.append("\nAnd now, you can type the message you want in the Message box.\n");
                    isSeted = true;
                }
                else ta_info.append("WARNING: The number e must be an odd number.\n");
            }
        }
        else if (src == but_e) {
            if (ta_msg.getText().length() == 0) ta_info.append("WARNING: You must type some text in the message box.\n");    
            else if (!isSeted) ta_info.append("WARNING: You must SET your key first.\n");
            else {  
                if (isEncrypted) {
                    isEncrypted = false;
                    ta_msg.setText(Decrypt(E));
                    ta_msg.setEnabled(true);
                    but_d.setEnabled(true);
                }
                else {
                    isEncrypted = true;    
                    ta_msg.setText(Encrypt(ta_msg.getText(), E));
                    ta_msg.setEnabled(false);
                    but_e.setEnabled(false);
                }
            }
        }
        else if (src == but_d) {
            if (ta_msg.getText().length() == 0) ta_info.append("WARNING: You must type some text in the message box.\n");    
            else if (!isSeted) ta_info.append("WARNING: You must SET your key first.\n");
            else {  
                if (isEncrypted) {
                    isEncrypted = false;
                    ta_msg.setText(Decrypt(D));
                    ta_msg.setEnabled(true);
                    but_e.setEnabled(true);
                }
                else {
                    isEncrypted = true;    
                    ta_msg.setText(Encrypt(ta_msg.getText(), D));
                    ta_msg.setEnabled(false);
                    but_d.setEnabled(false);
                }
            }
        }
        else if (src == but_reset) {
            Reset();    
        }
    }

    public void Reset() {
		ta_info.setText("Welcome to RSA Demo Applet.\nBefore generating the pair of public key and private key,\nyou must choice the ODD e number, and then press SET button.\n\n");
        ta_msg.setText("");
        ta_msg.setEnabled(true);
        tf_e.setText("");
        but_e.setEnabled(true);
        but_d.setEnabled(true);
        isSeted = isEncrypted = false;
    }
    
    public BigInteger ChineseRemainder(BigInteger res[]) {
        BigInteger multiplier;
        BigInteger uv[] = Euclid(P, Q);
        BigInteger e[] = new BigInteger[2];
        e[0] = uv[1].multiply(Q);
        e[1] = uv[0].multiply(P);
        return ((e[0].multiply(res[0])).add(e[1].multiply(res[1]))).mod(N);
    }
    
    public String Encrypt(String msg, BigInteger key) {
        byte swap[] = msg.getBytes();
        byte segment[];
        String str = null;
        int copies = swap.length / BLOCKSIZE;
        if (swap.length % BLOCKSIZE > 0) copies++;
        for (int i = 0; i < copies; i++) {
            segment = copyBytes(i, swap);
            ciphertext[i] = new BigInteger(segment);
            ciphertext[i] = ciphertext[i].modPow(key, N);
            segment = ciphertext[i].toByteArray();
            if (str == null) str = new String(segment);
            else str += new String(segment);
        }
        return str;
    }
    
    private byte[] copyBytes(int x, byte tmp[]) {
        byte swap[] = new byte[12];
        int count = 0;
        for (int i = x * BLOCKSIZE; i < (x+1) * BLOCKSIZE; i++) {
            if (i >= tmp.length) break;
            swap[count++] = tmp[i];
        }
        return swap;
    }
    
    public String Decrypt(BigInteger key) {
        int i = 0;
        byte swap[];
        String str = null;
        do {
            ciphertext[i] = ciphertext[i].modPow(key, N);
            swap = ciphertext[i].toByteArray();
            if (str == null) str = new String(swap);
            else str += new String(swap);
        } while (ciphertext[++i] != null);
        return str;
    }
    
    /*public String Decrypt(BigInteger key) {
        int i = 0;
        byte swap[];
        String str = null;
        BigInteger Dp = key.mod(P.subtract(ONE));
        BigInteger Dq = key.mod(Q.subtract(ONE));
        BigInteger res[] = new BigInteger[2];
        do {
            res[0] = ciphertext[i].modPow(Dp, P);
            res[1] = ciphertext[i].modPow(Dq, Q);
            ciphertext[i] = ChineseRemainder(res);
            swap = ciphertext[i].toByteArray();
            if (str == null) str = new String(swap);
            else str += new String(swap);
        } while (ciphertext[++i] != null);
        return str;
    }*/

    public boolean generatePQNTED(String e) {
        E = new BigInteger(e);
        if (E.mod(new BigInteger("2")).equals(ZERO)) return false;
        do {
            P = new BigInteger(128, 10, rand);
            Q = new BigInteger(128, 10, rand);
            T = (P.subtract(ONE)).multiply(Q.subtract(ONE));
        } while (!(E.gcd(T)).equals(ONE));
        N = P.multiply(Q);
        BigInteger tmp[] = Euclid(E, T);
        D = tmp[0];
        return true;
    }

    public BigInteger[] Euclid(BigInteger x, BigInteger y) {
        int n = 2;
        BigInteger r[] = new BigInteger[3];
        BigInteger q[] = new BigInteger[3];
        BigInteger u[] = new BigInteger[3];
        BigInteger v[] = new BigInteger[3];

        r[0] = x;
        r[1] = y;
        u[0] = new BigInteger("1");
        v[0] = new BigInteger("0");
        u[1] = new BigInteger("0");
        v[1] = new BigInteger("1");
        while (!r[(n-1)%3].equals(ZERO)) {
            q[n%3] = r[(n-2)%3].divide(r[(n-1)%3]);
            r[n%3] = r[(n-2)%3].remainder(r[(n-1)%3]);
            // Un = Un-2 - QnUn-1
            u[n%3] = u[(n-2)%3].subtract(q[n%3].multiply(u[(n-1)%3]));
            // Vn = Vn-2 - QnVn-1
            v[n%3] = v[(n-2)%3].subtract(q[n%3].multiply(v[(n-1)%3]));

            n++;
        }
        BigInteger result[] = new BigInteger[2];
        result[0] = u[(n-2)%3];
        result[1] = v[(n-2)%3];
        return result;
    }

	TextArea ta_info;
	TextArea ta_msg;
	TextField tf_e;
	Button but_set;
	Button but_reset;
	Button but_e;
	Button but_d;
	Label label1;
	Label label2;
	Label label3;
	//{{DECLARE_CONTROLS
	//}}
}
