package edu.buffalo.cse.cse486586.simpledynamo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.DataInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.io.DataOutputStream;
import java.util.Formatter;
import java.util.HashMap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDynamoProvider extends ContentProvider {

    static final String TAG = SimpleDynamoProvider.class.getSimpleName();
    static final int SERVER_PORT = 10000;

    static final String REMOTE_PORT0 = "11108";
    static final String REMOTE_PORT1 = "11112";
    static final String REMOTE_PORT2 = "11116";
    static final String REMOTE_PORT3 = "11120";
    static final String REMOTE_PORT4 = "11124";
    HashMap<String, ArrayList<String>> keys = new HashMap<String, ArrayList<String>>();


    String my_port = null;
    String my_hash = null;
    String my_Suc1 = null;
    String my_suc2 = null;
    String my_pred1 = null;
    String my_pred2 = null;
    String[] remotePorts = {REMOTE_PORT0, REMOTE_PORT1, REMOTE_PORT2, REMOTE_PORT3, REMOTE_PORT4};

    HashMap<String, ArrayList<String>> rep1 = new HashMap<String, ArrayList<String>>();
    HashMap<String, ArrayList<String>> rep2 = new HashMap<String, ArrayList<String>>();

    ArrayList<String> sortedports = new ArrayList<String>();
    HashMap<String, String> map_to_hash = new HashMap<String, String>();
    ArrayList<String> sortedhashes = new ArrayList<String>();

    public void recoverData() throws IOException {
        for (String file : getContext().fileList()) {
            getContext().deleteFile(file);
        }
        try {
            Socket s1 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(my_Suc1));
            DataOutputStream dos1 = new DataOutputStream(s1.getOutputStream());
            dos1.writeUTF("suc1//DATA");

            try {
                DataInputStream dis = new DataInputStream(s1.getInputStream());
                String result = dis.readUTF();

                for (String rec : result.split(";")) {
                    String key = rec.split("::")[0];
                    String value = rec.split("::")[1];
                    FileOutputStream outputStream;
                    Log.i(TAG, "Adding file: " + key);
                    outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());
                    ArrayList<String> temp = keys.get(my_port);
                    temp.add(key);
                    keys.put(my_port, temp);
                }
            } catch (Exception e) {
                Log.e(TAG, "recoverData: Device not ready yet");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Socket s3 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(my_pred1));
            DataOutputStream dos3 = new DataOutputStream(s3.getOutputStream());
            dos3.writeUTF("main//DATA");

            try {
                DataInputStream dis = new DataInputStream(s3.getInputStream());
                String result = dis.readUTF();
                String[] recSplits = result.split(";");

                for (String rec : result.split(";")) {
                    String key = rec.split("::")[0];
                    String value = rec.split("::")[1];
                    FileOutputStream outputStream;
                    Log.i(TAG, "Adding file: " + key);
                    outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());
                    ArrayList<String> temp = rep1.get(my_port);
                    temp.add(key);
                    rep1.put(my_port, temp);
                }
            } catch (Exception e) {
                Log.e(TAG, "recoverData: Device not ready yet");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Socket s4 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), Integer.parseInt(my_pred2));
            DataOutputStream dos4 = new DataOutputStream(s4.getOutputStream());
            dos4.writeUTF("main//DATA");

            try {
                DataInputStream dis = new DataInputStream(s4.getInputStream());
                String result = dis.readUTF();

                for (String rec : result.split(";")) {
                    String key = rec.split("::")[0];
                    String value = rec.split("::")[1];
                    FileOutputStream outputStream;
                    Log.i(TAG, "Adding file: " + key);
                    outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                    outputStream.write(value.getBytes());
                    ArrayList<String> temp = rep2.get(my_port);
                    temp.add(key);
                    rep2.put(my_port, temp);
                }
            } catch (Exception e) {
                Log.e(TAG, "recoverData: Device not ready yet");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    // Takes the list of available nodes and returns the ring order
    public ArrayList<String> getRingOrder(String[] ports) {

        ArrayList<String> hashes = new ArrayList<String>();
        ArrayList<String> ring_order = new ArrayList<String>();

        for (int i = 0; i < ports.length; i++) {

            int id = Integer.parseInt(ports[i]);
            id = id / 2;
            String idstr = String.valueOf(id);

            try {
                String hash = genHash(idstr);
                hashes.add(hash);
                map_to_hash.put(hash, ports[i]);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        Collections.sort(hashes);

        for (int j = 0; j < hashes.size(); j++) {
            ring_order.add(map_to_hash.get(hashes.get(j)));
        }

        int my_index = ring_order.indexOf(my_port);
        if (my_index == 0) {
            my_Suc1 = ring_order.get(1);
            my_suc2 = ring_order.get(2);
            my_pred1 = ring_order.get(4);
            my_pred2 = ring_order.get(3);
        } else if (my_index == 1) {
            my_Suc1 = ring_order.get(2);
            my_suc2 = ring_order.get(3);
            my_pred1 = ring_order.get(0);
            my_pred2 = ring_order.get(ring_order.size() - 1);
        } else if (my_index == ring_order.size() - 1 || my_index == ring_order.size() - 2) {
            my_Suc1 = ring_order.get((my_index + 1) % ring_order.size());
            my_suc2 = ring_order.get((my_index + 2) % ring_order.size());
            my_pred1 = ring_order.get(my_index - 1);
            my_pred2 = ring_order.get(my_index - 2);
        } else {
            my_Suc1 = ring_order.get((my_index + 1) % ring_order.size());
            my_suc2 = ring_order.get((my_index + 2) % ring_order.size());
            my_pred1 = ring_order.get(my_index - 1);
            my_pred2 = ring_order.get(my_index - 2);
        }

        Log.i(TAG, "P1: " + my_pred1 + "P2: " + my_pred2 + " S1: " + my_Suc1 + " S2: " + my_suc2);
        Log.i(TAG, "utility: The hashes " + hashes);
        Log.i(TAG, "utility: The ring order is " + ring_order);

        return ring_order;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
        Log.i(TAG, "onCreate: function");

        TelephonyManager tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String myPort = String.valueOf((Integer.parseInt(portStr) * 2));

        my_port = myPort;
        Log.i(TAG, "onCreate: My port is " + my_port);

        sortedports = getRingOrder(remotePorts);

        Log.i(TAG, "onCreate: The sorted ports obtained are " + sortedports);

        for (int i = 0; i < sortedports.size(); i++) {

            int id = Integer.parseInt(sortedports.get(i));
            id = id / 2;
            String idstr = String.valueOf(id);

            try {
                String hash = genHash(idstr);
                sortedhashes.add(hash);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        Log.i(TAG, "onCreate: The sorted hashes are " + sortedhashes);

        try {
            my_hash = genHash(portStr);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        Log.i(TAG, "onCreate: My hash value is " + my_hash);

        for (String i : sortedports) {
            keys.put(i, new ArrayList<String>());
            rep1.put(i, new ArrayList<String>());
            rep2.put(i, new ArrayList<String>());
        }

        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "In oncreate: Can't create a ServerSocket");
        }

        return false;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        Log.i(TAG, "delete: function");

        for (String file : getContext().fileList()) {
            getContext().deleteFile(file);
        }
        ArrayList<String> temp = keys.get(my_port);
        if (temp.contains(selection)) {
            temp.remove(selection);
            keys.put(my_port, temp);
            Log.e(TAG, "delete: Removing " + selection);
        }
        ArrayList<String> temp2 = rep1.get(my_port);
        if (temp2.contains(selection)) {
            temp2.remove(selection);
            rep1.put(my_port, temp2);
            Log.e(TAG, "delete: Removing " + selection);
        }
        ArrayList<String> temp3 = rep2.get(my_port);
        if (temp3.contains(selection)) {
            temp3.remove(selection);
            rep2.put(my_port, temp3);
            Log.e(TAG, "delete: Removing " + selection);
        }


        for (String p : sortedports) {
            if (!p.equals(my_port)) {
                try {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(p));
                    DataOutputStream dataout = new DataOutputStream(socket.getOutputStream());
                    dataout.writeUTF("DELETE::" + selection);
                    dataout.flush();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        Log.i(TAG, "getType: function");
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        Log.i(TAG, "insert: function");
        Log.i(TAG, "insert: The sorted hashes are " + sortedhashes);

        Log.i(TAG, "Insert: Received key to insert: " + (String) values.get("key"));

        String key_hash = null;
        try {
            key_hash = genHash(values.getAsString("key"));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Log.i(TAG, "insert: Received key_hash is " + key_hash);

        int sz = sortedhashes.size();
        String key_belongs_to = null;
        String succ1 = null;
        String succ2 = null;

        for (int i = 1; i < sortedhashes.size(); i++) {
            if (key_hash.compareTo(sortedhashes.get(i - 1)) > 0 && key_hash.compareTo(sortedhashes.get(i)) <= 0) {
                Log.i(TAG, "insert: Key belongs to " + sortedports.get(i));
                key_belongs_to = sortedports.get(i);
                if (i == sortedhashes.size() - 1) {
                    succ1 = sortedports.get(0);
                    succ2 = sortedports.get(1);
                } else if (i == sortedhashes.size() - 2) {
                    succ1 = sortedports.get(i + 1);
                    succ2 = sortedports.get(0);

                } else {
                    succ1 = sortedports.get(i + 1);
                    succ2 = sortedports.get(i + 2);
                }
            }
        }

        if (key_hash.compareTo(sortedhashes.get(sz - 1)) > 0 || key_hash.compareTo(sortedhashes.get(0)) <= 0) {
            Log.i(TAG, "insert: Key value is either bigger than the highest node or smallest than the first node. hence, it belongs to first node, i.e., " + sortedports.get(0));
            key_belongs_to = sortedports.get(0);
            succ1 = sortedports.get(1);
            succ2 = sortedports.get(2);
        }

        Log.i(TAG, "insert: Succ1 is " + succ1);
        Log.i(TAG, "insert: Succ2 is " + succ2);
        String succs[] = {succ1, succ2};

        if (key_belongs_to.equals(my_port)) {
            Log.i(TAG, "insert: Key belongs to me. ");

            FileOutputStream outputStream;

            try {
                //Inserting in me
                Log.i(TAG, "insert: Adding file in me.");
                outputStream = getContext().openFileOutput((String) values.get("key"), Context.MODE_PRIVATE);
                outputStream.write(values.get("value").toString().getBytes());
                Log.i(TAG, "insert: write successful");
                ArrayList<String> temp = new ArrayList<String>();
                Log.i(TAG, "insert: temp is " + temp);
                Log.i(TAG, "insert: keys.get(myport) is " + keys.get(my_port));
                temp = keys.get(my_port);
                temp.add((String) values.get("key"));
                keys.put(my_port, temp);
                Log.i(TAG, "insert: Inserted into keys hashmap");
                outputStream.close();
                int c = 1;
                //Sending key to my successors
                for (String successor : succs) {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor));

                    DataOutputStream dataout = new DataOutputStream(socket.getOutputStream());
                    dataout.writeUTF("I" + c + "::" + (String) values.get("key") + "::" + values.get("value").toString());
                    c++;
                    Log.i(TAG, "Insert: Sent replicated data to " + (String) values.get("key") + " to " + successor);
                }


            } catch (Exception e) {
                e.printStackTrace();
                Log.e(TAG, "File write failed");
            }
        } else {
            Log.i(TAG, "insert: Need to send key value from " + my_port);
            Log.i(TAG, "insert: to " + key_belongs_to);

            try {
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(key_belongs_to));

                DataOutputStream dataout = new DataOutputStream(socket.getOutputStream());
                dataout.writeUTF("I::" + (String) values.get("key") + "::" + values.get("value").toString());
                dataout.flush();

                Log.i(TAG, "Insert: Sent " + (String) values.get("key") + " to " + key_belongs_to);
                int c = 1;
                //Sending key to my successors
                for (String successor : succs) {
                    Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor));

                    DataOutputStream dataout2 = new DataOutputStream(socket2.getOutputStream());
                    dataout2.writeUTF("I" + c + "::" + (String) values.get("key") + "::" + values.get("value").toString());
                    c++;
                    Log.i(TAG, "Insert: Sent replicated data to " + (String) values.get("key") + " to " + successor);
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        // TODO Auto-generated method stub

        Log.i(TAG, "query: function");
        Log.i(TAG, "query: The sorted hashes are " + sortedhashes);

        String[] kv = {"key", "value"};
        MatrixCursor matcursor = new MatrixCursor(kv);

        Log.i(TAG, "query: The selection obtained is " + selection);

        if (selection.equals("@")) {

            Log.i(TAG, "In Query: Received selection is" + selection);

            for (int i = 0; i < keys.get(my_port).size(); i++) {
                String keyval = keys.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            for (int i = 0; i < rep1.get(my_port).size(); i++) {
                String keyval = rep1.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            for (int i = 0; i < rep2.get(my_port).size(); i++) {
                String keyval = rep2.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } else if (selection.equals("*")) {
            ArrayList<String> dist_keys = new ArrayList<String>();
            for (int i = 0; i < keys.get(my_port).size(); i++) {
                String keyval = keys.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    dist_keys.add(keyval);
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            for (int i = 0; i < rep1.get(my_port).size(); i++) {
                String keyval = rep1.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    dist_keys.add(keyval);
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            for (int i = 0; i < rep2.get(my_port).size(); i++) {
                String keyval = rep2.get(my_port).get(i);
                try {
                    FileInputStream fileInputStream = getContext().openFileInput(keyval);
                    InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                    BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                    String msgread = bufferedReader.readLine();
                    String[] columnvalues = new String[]{keyval, msgread};
                    dist_keys.add(keyval);
                    matcursor.addRow(columnvalues);
                    inputStreamReader.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            for (String p : sortedports) {
                if (!p.equals(my_port)) {
                    try {
                        Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                Integer.parseInt(p));
                        DataOutputStream dataout = new DataOutputStream(socket.getOutputStream());
                        dataout.writeUTF("*::");
                        dataout.flush();

                        try {
                            DataInputStream dis = new DataInputStream(socket.getInputStream());
                            String result1 = dis.readUTF();
                            Log.i(TAG, " In query: Result " + result1);
                            for (String rec : result1.split(";")) {
                                String key = rec.split("::")[0];
                                String value = rec.split("::")[1];
                                if (!dist_keys.contains(key)) {
                                    matcursor.addRow(new String[]{key, value});
                                    dist_keys.add(key);
                                }
                            }
                        } catch (Exception e) {
                            Log.e(TAG, "query: Rxd none");
                        }
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }

        } else {
            String key_hash = null;
            try {
                key_hash = genHash(selection);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            Log.i(TAG, "query: Received key_hash is " + key_hash);

            int sz = sortedhashes.size();
            String key_belongs_to = null;
            String succ1 = null;
            String succ2 = null;

            for (int i = 1; i < sortedhashes.size(); i++) {
                if (key_hash.compareTo(sortedhashes.get(i - 1)) > 0 && key_hash.compareTo(sortedhashes.get(i)) <= 0) {
                    Log.i(TAG, "query: Key belongs to " + sortedports.get(i));
                    key_belongs_to = sortedports.get(i);
                    if (i == sortedhashes.size() - 1) {
                        succ1 = sortedports.get(0);
                        succ2 = sortedports.get(1);
                    } else if (i == sortedhashes.size() - 2) {
                        succ1 = sortedports.get(i + 1);
                        succ2 = sortedports.get(0);
                    } else {
                        succ1 = sortedports.get(i + 1);
                        succ2 = sortedports.get(i + 2);
                    }
                }
            }

            if (key_hash.compareTo(sortedhashes.get(sz - 1)) > 0 || key_hash.compareTo(sortedhashes.get(0)) <= 0) {
                Log.i(TAG, "query: Key value is either bigger than the highest node or smallest than the first node. hence, it belongs to first node, i.e., " + sortedports.get(0));
                key_belongs_to = sortedports.get(0);
                succ1 = sortedports.get(1);
                succ2 = sortedports.get(2);
            }

            Log.i(TAG, "query: Succ1 is " + succ1);
            Log.i(TAG, "query: Succ2 is " + succ2);
            String succs[] = {succ1, succ2, key_belongs_to};

            ArrayList<String> dist_keys = new ArrayList<String>();
            try {

                //Sending key to my those it belongs
                for (String successor : succs) {
                    Socket socket2 = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successor));


                    DataOutputStream dataout2 = new DataOutputStream(socket2.getOutputStream());
                    dataout2.writeUTF("Q::" + selection);

                    try {
                        DataInputStream datain = new DataInputStream(socket2.getInputStream());
                        String result1 = datain.readUTF();
                        if (!result1.equals("null")) {
                            Log.i(TAG, " In query: Result " + result1);
                            if (!dist_keys.contains(selection)) {
                                matcursor.addRow(new String[]{selection, result1.split("::")[1]});
                            }
                            break;
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "query: Device might be down");
                    }
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return matcursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }


    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {


            ServerSocket serverSocket = sockets[0];

            Socket datasocket = null;
            InputStream instream = null;

            try {
                recoverData();
            } catch (IOException e) {
                e.printStackTrace();
            }

            try {
                while (true) {
                    datasocket = serverSocket.accept();

                    instream = datasocket.getInputStream();
                    DataInputStream datainstream = new DataInputStream(new BufferedInputStream(instream));

                    String message = datainstream.readUTF();

                    Log.i(TAG, "Servertask: Received message" + message);

                    if (message.startsWith("I::")) {

                        Log.i(TAG, "Servertask: Received message " + message);

                        String[] splits = message.split("::");
                        String rec_key = splits[1];
                        String rec_value = splits[2];

                        //Inserting in me
                        FileOutputStream outputStream;
                        Log.i(TAG, "Servertask: Adding file in me.");
                        outputStream = getContext().openFileOutput(rec_key, Context.MODE_PRIVATE);
                        outputStream.write(rec_value.getBytes());
                        ArrayList<String> temp = new ArrayList<String>();
                        temp = keys.get(my_port);
                        temp.add(rec_key);
                        keys.put(my_port, temp);
                        Log.i(TAG, "insert: Inserted into keys hashmap");
                        outputStream.close();
                    } else if (message.startsWith("DELETE")) {
                        keys.get(my_port).clear();
                        rep1.get(my_port).clear();
                        rep2.get(my_port).clear();
                        for (String file : getContext().fileList()) {
                            getContext().deleteFile(file);
                        }
                    } else if (message.startsWith("I1::")) {

                        Log.i(TAG, "Servertask: Received message I1" + message);

                        String[] splits = message.split("::");
                        String rec_key = splits[1];
                        String rec_value = splits[2];

                        //Inserting in me
                        FileOutputStream outputStream;
                        Log.i(TAG, "Servertask: Adding file in me.");
                        outputStream = getContext().openFileOutput(rec_key, Context.MODE_PRIVATE);
                        outputStream.write(rec_value.getBytes());
                        ArrayList<String> temp = new ArrayList<String>();
                        temp = rep1.get(my_port);
                        temp.add(rec_key);
                        rep1.put(my_port, temp);
                        Log.i(TAG, "insert: Inserted into rep1 hashmap");
                        outputStream.close();
                    } else if (message.startsWith("I2::")) {

                        Log.i(TAG, "Servertask: Received message I2" + message);

                        String[] splits = message.split("::");
                        String rec_key = splits[1];
                        String rec_value = splits[2];

                        //Inserting in me
                        FileOutputStream outputStream;
                        Log.i(TAG, "Servertask: Adding file in me.");
                        outputStream = getContext().openFileOutput(rec_key, Context.MODE_PRIVATE);
                        outputStream.write(rec_value.getBytes());
                        ArrayList<String> temp = rep2.get(my_port);
                        temp.add(rec_key);
                        rep2.put(my_port, temp);
                        Log.i(TAG, "insert: Inserted into rep2 hashmap");
                        outputStream.close();
                    } else if (message.equals("suc1//DATA")) {
                        String result = "";

                        for (String key : rep1.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        DataOutputStream dos = new DataOutputStream(datasocket.getOutputStream());
                        dos.writeUTF(result);
                        dos.flush();
                    } else if (message.equals("suc2//DATA")) {
                        String result = "";

                        for (String key : rep2.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        DataOutputStream dos = new DataOutputStream(datasocket.getOutputStream());
                        dos.writeUTF(result);
                        dos.flush();
                    } else if (message.equals("main//DATA")) {
                        String result = "";

                        for (String key : keys.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        DataOutputStream dos = new DataOutputStream(datasocket.getOutputStream());
                        dos.writeUTF(result);
                        dos.flush();
                    } else if (message.startsWith("*::")) {

                        Log.i(TAG, "Servertask: Received message " + message);

                        String result = "";

                        for (String key : keys.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        for (String key : rep1.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        for (String key : rep2.get(my_port)) {

                            try {
                                FileInputStream fileInputStream = getContext().openFileInput(key);
                                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                                result += key + "::" + bufferedReader.readLine() + ";";
                            } catch (FileNotFoundException e) {
                                Log.e(TAG, "Exception in Servertask");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        DataOutputStream dos = new DataOutputStream(datasocket.getOutputStream());
                        dos.writeUTF(result);
                        dos.flush();

                    } else if (message.startsWith("Q::")) {

                        Log.i(TAG, "Servertask: Received message " + message);
                        String msgsplit[] = message.split("::");
                        String result = "";

                        Log.i(TAG, "Servertask: Query: Key found");

                        FileInputStream fileInputStream = getContext().openFileInput(msgsplit[1]);
                        InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                        String msgread = bufferedReader.readLine();

                        DataOutputStream dataout = new DataOutputStream(datasocket.getOutputStream());
                        dataout.writeUTF("QR::" + msgread);
                        dataout.flush();
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }
}
