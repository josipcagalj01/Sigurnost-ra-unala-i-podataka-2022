# Vježba 1 - man in the middle napad

Tema tj. cilj prve vježbe bio je objasniti što je i pokazati kako dolazi do **man in the middle** napada, kako se izvodi i koje su njegove posljedice.

Glavno okruženje za izvođenje vježbe bio je Linux terminal.

Da bismo izveli spomenuti napad prvo je trebalo korištenjem Docker tehnologije stvoriti tri virtualna računala: 

1. station_2 → poslužitelj
2. station_1  → korisnik koji se spaja na poslužitelj
3. evil_station → računalo pomoću kojeg se vrši napad

Da bi napad bio izvediv, tj. imao smisla, “žrtve” bi trebale komunicirati. To je učinjeno tako da je station_2 počeo osluškivati na određenom portu, a station_1 se povezao na station-1 na tom istom portu. Sad ova dva računala mogu razmjenjivati poruke u oba smjera. U oba slučaja korištena je naredba **netcat**.

Station_1 i 2 komuniciraju što znači da evil_station, koji se nalazi u istoj lokalnoj mreži kao i ova dva, može početi s napadom: 

Prije opisa što točno evil-station radi treba napomenuti da, kad jedno računalo šalje nešto drugom računalu u istoj lokalnoj mreži, mora znati njegovu MAC adresu. Prije samog prosljeđivanja sadržaja svakom uređaju u mreži dolazi upit ima li on MAC adresu navedenu u paketu koji pošiljatelj šalje. Ukoliko ima, njemu će se paket proslijediti. Dakle, da bi napadač presreo poruku, mora prevariti pošiljatelja predstavljajući se kao primatelj, tj. predstavljajući primateljevu, dakle tuđu, MAC adresu kao vlastitu.

Nakon ovog teorijskog uvoda jasno kako (zbog čega) napadač:

- pomoću naredbe **arpspoof** MAC adresu računala station_2 predstavlja kao svoju
- počinje pratiti što šalje station_1 korištenjem naredbe **tcpdump**
- izvodi i **denail of service (DoS)** napad ukoliko presretenu poruku ne proslijedi primatelju kojem je uistinu bila namijenjena. Na vježbi se blokirala komunikacija samo u jednom smjeru (station_1 uredno je primao poruke s poslužitelja (station_2)).

Izvođenjem man in the middle napada te promatranjem onoga što se događa po njegovu započinjanju uvidjelo se:

- **Presretanjem komunikacije narušava se povjerljivost.**
- Da je evil_station **mijenjao sadržaj** presretene poruke prije prosljeđivanja računalu station_2 **narušio bi** se i **integritet** te poruke.
- Izvođenjem **DoS** napada tj. onemogućavanjem računalu station_2 primanje poruke poslane s računala station_1 **narušava se** i **dostupnost**.