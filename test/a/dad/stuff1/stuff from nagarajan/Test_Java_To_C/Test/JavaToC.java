public class JavaToC {

    public native void testC();

    static {
        System.loadLibrary("HelloWorld");
    }

    public static void main(String[] args) {
        new JavaToC().testC();
    }
}