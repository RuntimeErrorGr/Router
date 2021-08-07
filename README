Lăbău Cristea Andrei Liviu 324CB

1) Parsarea tabelei de rutare.
	Am implementat parsarea tabelei de rutare.
	Pentru parsarea tabelei de rutare din fisier text am, folosit un
	typedef struct my_rtable_entry. 
	Initial am parcurs fisierul pentru a numara cate intrari vor exista in tabela
	de rutare cu ajutorul functiei int count_entries() pe
	care am definit-o in skel.c. Apoi am alocat un array de dimensiune
	numar_intrari * rtable_size.
	Se citeste a 2a oara fisierul linie cu linie pana la EOF. Fiecare linie este impartita in 4 substringuri cu strtok: prefix ip, next hop ip,
	masca si interfata si se populeaza arrayul cu informatiile citite cu ajutorul
	metode void myRead_rtable();

2) Implementarea protocolului ARP.
	Pentru a trata pachetele ce incapsuleaza mesaje de tip ARP am considerat
	urmatoarele cazuri:
		2.1) Routerul poate primi un pachet ARP, caz in care campul type din
		headerul ethernet este 0x0806.
			2.1.1) Pachetul primit este ARP reply, caz in care se proceseaza
			pachetul, tabela ARP este updatata cu adresa MAC sursa din pachet si se proceseaza toate pachetele care sunt in asteptare in coada spre
			trimitere. Am considerat ca un astfel de pachet se poate primi in
			urma efectuarii unui ARP request.
			2.1.2) Pachetul primit este ARP request, caz in care se verifica 
			destinatia pachetului. Daca acesta este destinat routerului, se 
			trimite un ARP reply cu adresa MAC a interfetei routerului care a 
			primit pachetul initial.
		2.2) Routerul poate efectua un ARP request catre un host in scopul aflarii
		adresei sale MAC. ARP request se efectueaza, daca in urma apelului 
		functiei getARPentry(), pointerul intors este NULL, deci nu exista o 
		intrare corespunzatoare pentru respectiva adresa ip. Inainte de a trimite
		ARP request se face o copie a pachetului initial si se introduce intr-o
		coada de asteptare. Se creeaza un header ethernet cu adresa broadcast
		ff:ff:ff:ff:ff:ff si se incapsuleaza si trimite un ARP request catre adresa
		next hopului corespunzator din tabela de rutare.

3) Implementarea procesului de dirijare.
	Pentru implementarea procesului de dirijare am urmat pasii procedurii din
	enunt: dupa primirea pachetului se verifica daca este incapsulat ip si daca
	este ICMP se extrag headerele corespunzatoare pentru a fi folosite ulterior.
	Se verifica cazurile de exceptie: ttl <= 1 -> se trimite ICMP timeout si
	checksum gresit -> se arunca pachetul. Se decrementeaza ttl, se updateaza 
	checksum si se cauta in tabela de rutare o intrare potrivita conform LPM.
	Mentionez ca nu am implementat cautarea in tabela in mai putin de O(n).
	Odata ce a fost gasita intrarea in tabela de rutare se verifica daca routerul
	cunoaste adresa MAC a next hopului. Daca nu, face ARP request. Daca da, 
	se trimite pachetul cu MAC sursa si MAC destinatie corespunzatoare.
	In cazul in care nu exista o intrare corespunzatoare in tabela de rutare se
	intoarce un mesaj de ICMP destination unreachable

4) Implementarea protocolului ICMP.
	Pentru protocolul ICMP am tratat cele 3 cazuri descrise in enunt:
	4.1) La primirea unui echo request se verifica destinatia pachetului. 
	Daca acesta este destinat routerului se trimite un mesaj echo reply. Altfel se arunca pachetul.
	4.2) La primirea unui pachet cu un ttl <= 1 se trimite un ICMP time exceeded
	si se arunca pachetul.
	4.3) Daca routerul nu stie sa forwardeze mai departe pachetul (nu are o 
	intrare corespunzatoare in tabela de rutare pentru adresa ip destinatie a
	pachetului) se intoarce un mesaj de tipul ICMP destination unreachable.

	Mentionez ca am folosit ca sursa de documentatie principala laboratorul 4
	si de asemenea am folosit bucati de cod pe care le implementasem la acel
	laborator: metodele de check TTL, check Checksum, update Checksum si
	cautarea in tabela de routare.
