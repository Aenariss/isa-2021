# ISA Projekt 2021
### Autor: Vojtech Fiala (xfiala61)

### Popis:
Vytvořte komunikující aplikaci podle konkrétní vybrané specifikace pomocí síťové knihovny BSD sockets (pokud není ve variantě zadání uvedeno jinak). Projekt bude vypracován v jazyce C/C++. Pokud individuální zadání nespecifikuje vlastní referenční systém, musí být projekt přeložitelný a spustitelný na serveru merlin.fit.vutbr.cz pod operačním systémem GNU/Linux. Program by měl být přenositelný. Hodnocení projektů může probíhat na jiném počítači s nainstalovaným OS GNU/Linux, včetně jiných architektur než Intel/AMD, distribucí či verzí knihoven. Pokud vyžadujete minimální verzi knihovny (dostupnou na serveru merlin), jasně tuto skutečnost označte v dokumentaci a README.

### Odevzdání
Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte elektronicky přes IS. Soubor nekomprimujte.
Termín odevzdání je 15.11.2021 (hard deadline). Odevzdání e-mailem po uplynutí termínu, dodatečné opravy či doplnění kódu není možné.
Odevzdaný projekt musí obsahovat:  
- Soubor se zdrojovým kódem (dodržujte jména souborů uvedená v konkrétním zadání)  
- Funkční Makefile pro překlad zdrojového souboru  
- Dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky, návrhu aplikace, popis implementace, základní informace o programu, návod na použití.  
V dokumentaci se očekává následující: titulní strana, obsah, logické strukturování textu, přehled nastudovaných informací z literatury, popis zajímavějších pasáží implementace, použití vytvořených programů a literatura.  
Soubor README obsahující krátký textový popis programu s případnými rozšířeními/omezeními, příklad spuštění a seznam odevzdaných souborů,
další požadované soubory podle konkrétního typu zadání.   
Pokud v projektu nestihnete implementovat všechny požadované vlastnosti, je nutné veškerá omezení jasně uvést v dokumentaci a v souboru README.  
Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého vlastního výběru. Zvolené řešení popište v dokumentaci.  
Při řešení projektu respektujte zvyklosti zavedené v OS unixového typu (jako je například formát textového souboru).  
Vytvořené programy by měly být použitelné a smysluplné, řádně komentované a formátované a členěné do funkcí a modulů. Program by měl obsahovat nápovědu informující uživatele o činnosti programu a jeho parametrech. Případné chyby budou intuitivně popisovány uživateli.  
Aplikace nesmí v žádném případě skončit s chybou SEGMENTATION FAULT ani jiným násilným systémovým ukončením (např. dělení nulou).  
Pokud přejímáte krátké pasáže zdrojových kódů z různých tutoriálů či příkladů z Internetu (ne mezi sebou), tak je nutné vyznačit tyto sekce a jejich autory dle licenčních podmínek, kterými se distribuce daných zdrojových kódů řídí. V případě nedodržení bude na projekt nahlíženo jako na plagiát.  
Konzultace k projektu podává vyučující, který zadání vypsal.  
Sledujte fórum k projektu, kde se může objevit dovysvětlení či upřesnění zadání.  
Před odevzdáním zkontrolujte, zda projekt obsahuje všechny potřebné soubory a také jste dodrželi jména odevzdávaných souborů pro konkrétní zadání. Zkontrolujte, zda je projekt přeložitelný.  

### Hodnocení
Hodnocení projektu:
- Maximální počet bodů za projekt je 20 bodů.
- Maximálně 15 bodů za plně funkční aplikaci.
- Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání, dokumentace se nehodnotí.  

Příklad kriterií pro hodnocení projektů:  
- nepřehledný, nekomentovaný zdrojový text: až -7 bodů
- nefunkční či chybějící Makefile: až -4 body
- nekvalitní či chybějící dokumentace: až -5 bodů
- nedodržení formátu vstupu/výstupu či konfigurace: -10 body
- odevzdaný soubor nelze přeložit, spustit a odzkoušet: 0 bodů
- odevzdáno po termínu: 0 bodů
- nedodržení zadání: 0 bodů
- nefunkční kód: 0 bodů
- opsáno: 0 bodů (pro všechny, kdo mají stejný kód), návrh na zahájení disciplinárního řízení.


### Zadanie:

Vašou úlohou je:

- Zachytiť komunikáciu medzi poskytnutým serverom a klientom  
- Implementovať vlastný Wireshark dissector pre daný protokol  
- Implementovať kompatibilného klienta pre daný protokol  

#### Upresnenie zadania:

###### 1. Zachytenie protokolovej komunikácie   
   
K zadaniu projektu bude dodaný virtuálny stroj s referenčným klientom a serverom. Vhodným použitím klienta vygenerujte komunikáciu medzi klientom a serverom ktorú zachytíte pomocou nástroja Wireshark do PCAPu. Táto komunikácia bude slúžiť ako základ pre Vašu implementáciu. Formát protokolu popíšte do dokumentácie.   

###### 2. Implementovanie Wireshark dissectoru

Podporu nástroja Wireshark pre sieťové protokoly je možné rozšíriť pomocou vlastných dissectorov implementovaných v jazyku C alebo Lua. Dissectory umožňujú prezentovať protokolové dáta v užívateľsky prívetivejšej forme.   

Naštudujte si tvorbu dissectorov, napr. z Wireshark wiki ([1-3]). Implementuje dissector pre zachytený protokol. Detaily formátu dissectoru zvoľte podľa vlastného uváženia, cieľom je aby výsledná forma bola jasne pochopiteľná pre užívateľa. Návrh dissectoru dôkladne popíšte v dokumentácii.   

###### 3. Implementovanie kompatibilného klienta

Na základe nadobudnutých znalostí o protokole naimplementuje kompatibilného klienta. Klient by mal byť schopný slúžiť ako "drop-in" náhrada referenčného klienta, ako vo formáte spustenia tak aj výstupu. Pri nejasnostiach sa riaďte chovaním referenčného klienta. Váš klient môže obsahovať pridanú funkcionalitu, mal by však byť striktne kompatibilný s referenčnou implementáciou. Dokumentácia bude obsahovať popis akýchkoľvek rozšírení, popisovať funkcionalitu referenčnej implementácie nie je nutné.   

Klient bude implementovaný v jazykoch C/C++ a súčasťou riešenia bude Makefile ktorý po spustení vytvorí spustiteľného klienta s názvom client. Riešenie by malo byť preložiteľné a spustiteľné na dodanom virtuálnom stroji.   

###### 4. Dokumentácia

Dokumentáciu je možné písať v jazykoch čeština, slovenčina alebo angličtina a vytvoriť v ľubovolnom nástroji (LaTeX, Microsoft Word, LibreOffice Writer, org-mode, Pandoc, ...), výsledkom však bude PDF súbor.    
Obsahom dokumentácie bude analýza zachytenej komunikácie, popis protokolu, návrhu dissectoru a prípadných rozšírení klienta. Dokumentácia bude hodnotená nielen po technickej (obsahovej), ale aj po formálnej (jazykovej a prezentačnej) stránke. Všetky použité zdroje budú korektne citované v súlade s [4].   

##### Odovzdanie projektu:

Projekt bude odovzdaný ako archív formátu tar bez komprimácie s názvom xlogin99.tar.  
Archív bude obsahovať:  
- dokumentáciu (manual.pdf)
- zachytenú komunikáciu (isa.pcap)
- dissector (isa.lua)
- Makefile
- zdrojové kódy klienta

##### Literatúra:

- [1] (https://gitlab.com/wireshark/wireshark/-/wikis/Lua)
- [2] (https://gitlab.com/wireshark/wireshark/-/wikis/Lua/Dissectors)
- [3] (https://gitlab.com/wireshark/wireshark/-/wikis/Lua/Examples)
- [4] (https://www.fit.vut.cz/study/theses/citations/.cs)
