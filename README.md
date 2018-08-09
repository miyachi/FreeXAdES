# FreeXAdES
FreeXAdES is a simple implementation of XAdES for long-term signature introductory / study. FreeXAdES can be executed only with the Java standard library.

# Requirement:
 Eclipse IDE for Java Developers.<br/>
  Version: Mars or after (ex:Oxygen)<br/>
  Java: Java8 or after<br/>
  Other: JUnit4 (eclipse standard library)<br/>

# Import and Run from GitHub:
 Menu:<br/>
  [File]-[Import...]<br/>
 Select:<br/>
  [Git]-[Projects from Git]<br/>
  click [Next>]<br/>
 Select:<br/>
  [Clone URI]<br/>
  click [Next>]<br/>
 URI:<br/>
  "https://github.com/miyachi/FreeXAdES"<br/>
  click [Next>]<br/>
 Branch Selection:<br/>
  click [Next>]<br/>
 Directory:<br/>
  "C:\Users\($NAME)\workspace\FreeXAdES"<br/>
  click [Next>]<br/>
  *NOTE.1 The setting path of Directory should be FreeXAdES under the workspace.<br/>
 Select:<br/>
  [Import using the New Project wizard]<br/>
  click [Next>]<br/>
 Wizards:<br/>
  [Java]-[Java Project]<br/>
  click [Next>]<br/>
 Poject name:<br/>
  "FreeXAdES"<br/>
  click [Next>]<br/>
  *NOTE.2 Location path is the same as "C:\Users\($NAME)\workspace\FreeXAdES" in *NOTE.1.<br/>
 Libraries:<br/>
  click [Add Library]<br/>
 Add Library:<br/>
  select [JUnit]<br/>
  click [Next>]<br/>
 JUnit Library version:<br/>
  select [JUnit 4]<br/>
  click [Finish]<br/>
 Java Setting:<br/>
  click [Finish]<br/>

# Run JUnit
 Open:<br/>
  FreeXAdeS/src/jp/langedge/FreeXAdES/IFreeXAdESTest.java<br/>
 Menu:<br/>
  [Run]-[Run]<br/>

# Run Sample (Not NEED Eclipse Env)
 Windows:<br/>
  CMD> cd test<br/>
  CMD> FxSample.bat<br/>
 Linux:<br/>
  $ cd test<br/>
  $ chmod +x *.sh<br/>
  $ ./FxSample.sh<br/>

# Document (Japanese)
  http://eswg.jnsa.org/matsuri/201605/20160523-S4-miyachi.pdf<br/>
  http://eswg.jnsa.org/matsuri/201805/20180523-L2-miyachi.pdf<br/>

end.
