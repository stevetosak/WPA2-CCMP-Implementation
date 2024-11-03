package server;

public class Benchmark {
    long start = -1;
    long end = -1;

    void start(){
        this.start = System.nanoTime();
    }
    void end(){
        this.end = System.nanoTime();
    }

    void printTime(){
        if(start == -1 || end == -1){
            System.out.println("cant benchmark");
            return;
        }
        System.out.println("Execution time: " + ((end - start) / (Math.pow(10,6))) + "ms");
    }
}
