package dz.univ.usp;

public final class PasswordExperiment {
    private PasswordExperiment() {}

    public static void main(String[] args) {
        PasswordService svc = new Pbkdf2PasswordService();
        String pw = "Hadjer2026!";

        String h1 = svc.hash(pw);
        String h2 = svc.hash(pw);
        System.out.println("1. hash #1: " + h1);
        System.out.println("   hash #2: " + h2);
        System.out.println("2. hashes equal?            " + h1.equals(h2) + "   (expected false)");
        System.out.println("3. correct password         " + svc.verify(pw, h1) + " / "
                + svc.verify(pw, h2) + "   (expected true / true)");
        System.out.println("4. wrong password           " + svc.verify("Hadjer2026?", h1)
                + "   (expected false)");
        System.out.println("5. malformed hash 'garbage' " + svc.verify(pw, "garbage")
                + "   (expected false, no exception)");

        String outdated = h1.replace("i=600000", "i=100000");   // pretend it was made with a weaker cost
        System.out.println("6. needsRehash current      " + svc.needsRehash(h1) + "   (expected false)");
        System.out.println("   needsRehash outdated     " + svc.needsRehash(outdated) + "   (expected true)");
        System.out.println("   needsRehash malformed    " + svc.needsRehash("garbage") + "   (expected true)");
    }
}