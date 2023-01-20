# Vježba 5 - online i offline napadi na lozinke

# Uvod

Tema ove laboratorijske vježbe bila je pokazati kako se izvode online i offline napadi s ciljem dobivanja informacije o lozinci potrebnoj za prijavu, uvidjeti osobitosti svakog napada i prokomentirati moguće metode zaštite. Konkretno, pokušavalo se doznati lozinke za pristup Linux serveru, a za izvođenje vježbe korišten je WSL.

# Online napad

Prije svega, trebalo je pronaći server na koji ćemo se pokušati spojiti. Da bismo došli do traženog servera pomoću alata **nmap** smo skenirali lokalnu mrežu i dobili informaciju kako se zove naš server tj. koja mu je adresa. To smo izveli naredbom: `nmap -v 10.0.15.0/28`

Nakon toga, pokušali smo se prijaviti u svoj korisnički račun na odgovarajućem serveru naredbom, u mome slučaju `ssh cagalj_josip@cagaljjosip.local`. Kako ne znamo lozinku, pokušat ćemo doći do nje online napadom.

Online napad izvodi se uzimajući lozinke za koje smatramo da bi mogle biti točne te pokušavajući se prijaviti pomoću njih. Naravno, napad se može izvesti na više načina. Na vježbama je za njegovo izvođenje korišten alat **hydra**.

## Korištenje grube sile (eng. brute force attack)

Napad se vrši pokretanjem sljedeće naredbe: `hydra -l cagalj_josip -x 4:6:a cagaljjosip.local -V -t 6 ssh`. Hydri smo dali informaciju da se lozinka sastoji samo od malih slova te da je duljine od 4 do 6 znakova. Napad se izvodi tako da Hydra krene isprobavati sve moguće lozinke dok ne dođe do točne. Ovaj napad je jako spor i u praksi neisplativ jer je broj mogućih kombinacija jako velik, a kad bi se lozinka sastojala još od nekih kategorija znakova i bila dulja, napad bi trajao još dulje. Kako napad traje dugo (vrijeme se mjeri u godinama), odustalo se od ove mogućnosti.

## Napad korištenjem rječnika (eng. dictionary attack)

Ovaj napad također spada u online napade. Razlika je u tome što su lozinke, među kojima bi mogla biti i tražena, pohranjene u nekom rječniku. Rječnik je popis lozinki koje bi se, sukladno nekoj metodologiji, mogle koristiti za autentifikaciju korisnika čiju lozinku za pristup nekom resursu želimo saznati.

Da bismo izveli ovaj napad prvo je trebalo preuzeti rječnik s mogućim lozinkama pomoću alata **wget naredbom** `wget -r -nH -np --reject "index.html*" http://challenges.local/dictionary/g1/`.

Za izvođenje napada koristili smo alat hydra,a izveli ga naredbom `hydra -l cagalj_josip -P dictionary/g1/dictionary_online.txt cagaljjosip.local -V -t 4 ssh`. Trajanje ovog napada je manje nego li kod onoga korištenjem grube sile, što je i logično jer je broj lozinki koje treba isprobati manji. Po završetku napada, koji je u mome slučaju trajao nešto duže jer se lozinka nalazila pri kraju rječnika, uspješno sam se prijavio u svoj korisnički račun korištenjem spomenute `ssh cagalj_josip@cagaljjosip.local` naredbe i dobivene lozinke “tongof”.

## Zaštita od online napada

Online napadima pokazanim na vježbi bi se vjerojatno ne bi mogao izvršiti napad na neki ozbiljnije zaštićen sustav. Naime, jedna od metoda zaštite bila bi onemogućavanje prijave u neki korisnički račun na neko vrijeme nakon nekog broja neuspješnih prijava te određivanje najvećeg mogućeg broja pokušaja prijava u, npr. jednom danu.

Kompleksnost (broj različitih tipova znakova od kojih se sastoji lozinka) i veća duljina lozinki jedan su od načina zaštite od napada korištenjem grube sile, a korištenje “neočekivane” lozinke, tj. one koja metodologijom izrade rječnika ne bi bila prepoznata kao moguća, tj. uvrštena u isti. Ako se na poslužitelju ne pohranjuju same lozinke već njihova hash vrijednost korištenje sporih kriptografskih hash funkcija i onih koje zauzimaju mnogo radne memorije produljuju vrijeme potrebno da se dobije odgovor i time usporavaju napad, pa i do neisplativosti.

# Offline napad

Osnova za izvođenje offline napada, napda bez povezivanja na poslužitelj, tj. višestrukih pokušaja autentifikacije jest poznavanje nekih metapodataka, odnosno nekih informacija pomoću kojih bismo mogli doći do željene lozinke.

U konkretnom primjeru, pokušavali smo doći do lozinke na temelju sljedećih informacija: duljina lozinke je točno 6 znakova, sastoji se samo od malih slova te smo znali hash vrijednost koju hash funkcija korištena za pohranu lozinki na promatranom poslužitelju daje za traženu lozinku.

## Korištenje grube sile (eng. brute force attack)

Napad se vrši pokretanjem sljedeće naredbe `hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10`. Alatu **hashcat** smo dali spomenute poznate podatke i hash vrijednost. Napad se izvodi tako da se za sve moguće lozinke duljine 6 znakova koje se sastoje od malih slova odredi hash vrijednost te se provjeri odgovara li proslijeđenoj hash vrijednosti. Ukoliko jest, lozinka je pogođena, a ako nije postupak se ponavlja. Kao i kod oline napada, broj mogućih lozinki je jako velik pa se od ovog napada odustalo.

## Napad korištenjem rječnika (eng. dictionary attack)

Kao i kod online napada korištenjem rječnika, i ovdje je potreban rječnik u kojem su zapisane moguće lozinke, a sam napad se izvodi tako da se za svaku lozinku iz rječnika odredi hash vrijednost korištenjem hash funkcije koja se koristi za na promatranom poslužitelju i provjeri odgovara li hash vrijednosti koju imamo na početku napada.

Naredba za izvršenje napada je `hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10`. 

Po završetku napada dobili smo lozinku za prijavu u korisnički račun koji smo napadali te smo se mogli prijaviti kao i u prethodnom dijelu vježbe.

## Zaštita od offline napada

Jedna od metoda zaštite jest ona kojom se bavila prethodna vježba, a to je pohranjivanje hash vrijednosti lozinki umjesto njihove pohrane “u čisto”. Ako se pri tome koriste spore kriptografske hash funkcije i one koje zauzimaju mnogo radne memorije, offline napad se može dosta usporiti, pa i do neisplativosti. Isto tako, ako se hash vrijednost pohranjena na poslužitelju dobiva pomoću lozinke i “soli” koja se nasumično stvara, opisane napade postaje puno teže izvesti i puno duže traju. Što se tiče duljine i “sadržaja” samih lozinki, metode zaštite su iste kao i one korištene za zaštitu protiv online napada.