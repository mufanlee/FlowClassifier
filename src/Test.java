import util.SystemConfigurator;

public class Test {
    public static void main(String []args) {
        //String csvHeader = SystemConfigurator.read("csv");
        String arffHeader = SystemConfigurator.read("arff");
        //System.out.println(csvHeader);
        System.out.println(arffHeader);
    }
}
