# FreeXAdES
FreeXAdES is a simple implementation of XAdES for long-term signature introductory / study. FreeXAdES can be executed only with the Java standard library.

# Requirement:
 Eclipse IDE for Java Developers.
 Version：Mars or after (ex:Oxygen)
 Java：Java8 or after
 Other：JUnit4 (eclipse standard library)

# Import and Run from GitHub:
 Menu:
  [File]-[Import…]
 Select:
  [Git]-[Projects from Git]
  click [Next>]
 Select:
  [Clone URI]
  click [Next>]
 URI:
  "https://github.com/miyachi/FreeXAdES"
  click [Next>]
 Branch Selection:
  click [Next>]
 Directory:
  "C:\Users\($NAME)\workspace\FreeXAdES"
  click [Next>]
  *NOTE.1 The setting path of Directory should be FreeXAdES under the workspace.
 Select:
  [Import using the New Project wizard]
  click [Next>]
 Wizards:
  [Java]-[Java Project]
  click [Next>]
 Poject name:
  "FreeXAdES"
  click [Next>]
  *NOTE.2 Location path is the same as "C:\Users\($NAME)\workspace\FreeXAdES" in *NOTE.1.
 Libraries:
  click [Add Library]
 Add Library:
  select [JUnit]
  click [Next>]
 JUnit Library version:
  select [JUnit 4]
  click [Finish]
 Java Setting:
  click [Finish]

# Run JUnit
 Open:
  FreeXAdeS/src/jp/langedge/FreeXAdES/IFreeXAdESTest.java
 Menu:
  [Run]-[Run]

# Run Sample (Not NEED Eclipse Env)
 Windows:
  > cd test
  > FxSample.bat
 Linux:
  $ cd test
  $ chmod +x *.sh
  $ ./FxSample.sh

end.
