Denna katalog innehåller kompatibilitetskod för Google Chrome 35 / Chromium 35
och senare versioner. Koden består av en Javascript-fil som du behöver
installera i webbläsaren samt ett serverprogram som måste köras när du
använder webbsidor med BankID-inloggning.

För att kompilera koden, skriv:

    make

Då skapas en programfil som heter "npcompatsrv". För att starta den, skriv:

    ./npcompatsrv

Om FriBID är installerat i en av standardkatalogerna så hittas det automatiskt
och programmet kommer att säga "Server started on port 20048". Annars skrivs
ett felmeddelande ut.

Installera sedan fribid_npapi_compat.user.js i webbläsaren.
För Chrome / Chromium gör du så här:

    1) Tryck på ≡ knappen, och Tools --> Extensions.
    2) Öppna npcompatsrv-katalogen i en filhanterare.
    3) Drag och släpp filen "fribid_npapi_compat.user.js" till listan
       över extensions i webbläsaren (alternativt till texten där det
       står att inga extensions är installerade).
    4) Tryck på "Add".
    5) Klart. Nu ska "FriBID NPAPI Compatibility" dyka upp i listan.

Om du använder Chrome/Chromium 38 eller en senare version så måste du köra
din webbläsare med följande kommando:

  chromium --allow-running-insecure-content

Nu kan du använda webbsidor med BankID-inloggning. Det kommer dock att synas
en gul varningstriangel i webbläsaren när du använder npcompatsrv. Detta
händer eftersom servern kör HTTP och inte HTTPS. Men eftersom servern endast
kör lokalt så är detta inget problem.

