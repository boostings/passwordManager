//for Rule 4 STR03-J
BigInteger x = new BigInteger("530500452766");
String s = x.toString();  // Valid character data
byte[] byteArray = s.getBytes();
String ns = new String(byteArray);  
x = new BigInteger(ns);

//for Rule 5
class ListUtility {
  private static void addToList(List<String> list, String str) {
    list.add(str);     // No warning generated
  }

  public static void main(String[] args) {
    List<String> list = new ArrayList<String> ();
    addToList(list, "42");
    System.out.println(list.get(0));
  }
}

//for Rule 6
private Object myState = null;

// Sets some internal state in the library
void setState(Object state) {
  if (state == null) {
    // Handle null state
  }

  // Defensive copy here when state is mutable

  if (isInvalidState(state)) {
    // Handle invalid state
  }
  myState = state;
}

// Performs some action using the state passed earlier
void useState() {
  if (myState == null) {
    // Handle no state (e.g., null) condition
  }
  // ...
}
