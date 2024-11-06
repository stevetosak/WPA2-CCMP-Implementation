package server;

public class DataPacket {
    StringBuilder data = new StringBuilder();

    public void add(String data){
        this.data.append(data).append(":");
    }

    public String getData(){
        return data.deleteCharAt(data.lastIndexOf(":")).toString();
    }

    public void place(String data){ // place already formatted string
        this.data = new StringBuilder(data);
    }

    public static String[] parse(String data){
        return data.split(":");
    }
}
