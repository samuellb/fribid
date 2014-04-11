Denna katalog innehåller testskript som kan användas för att testa att
FriBID fungerar korrekt. Skripten kontrollerar dock inte giltigheten hos
certifikaten, och kan inte heller skapa giltiga certifikat, utan enbart
testcertifikat. Följande skript finns tillgängliga:

sign.sh - Detta skript testar skapande av signaturer. Du behöver ha ett
certifikat (en e-legitimation) för att köra testet, men oavsett så ska
det dyka upp ett fönster där man får välja certifikat och ange lösenord
när man kör skriptet.

reqcert.sh - Detta skript testar en "certifikatförfrågan", vilket är det
första steget vid hämtning av en e-legitimation. Du bör få upp ett
fönster där du får välja ett lösenord, och efter att ha kört testet ska
det dyka upp en testfil i "~/cbt". Det andra steget vid hämtning av en
e-legitimation kan för närvarande inte testas med dessa skript.
