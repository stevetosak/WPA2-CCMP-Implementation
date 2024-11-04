package server;

import javax.xml.crypto.Data;

public class DataPacket {
    StringBuilder stringBuilder = new StringBuilder();

    public void add(String data){
        stringBuilder.append(data).append(":");
    }

    public String getData(){
        return stringBuilder.toString();
    }

    public static String[] parse(String data){
        return data.split(":");
    }
}
