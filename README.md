# Simulation of WPA2 Protocol and CCMP Encryption using Web Sockets in Јava. 
*Stefan Toskovski*


## Архитектура на решението

 Овој код го симулира WPA2 стандардот и CCMP протоколот. Се состои од едноставен сервер (Access Point) кој слуша на сокет и клиент кој праќа пакети на тој сокет.
* Во класата `ClientHandler` е имплементирана логиката на симулираниот AccessPoint(AP).
* Во класата `SocketClient` e имплементирана логиката за клиентот.
*  Бидејќи се работи со сокети, пораките (пакетите) што се испраќаат помеѓу AP и Клиентот се стрингови. За да се воспостави структура на пакетите, со цел да се праќаат потребните информации, секој дел од пакетот, во стрингот е одделен со " : ". *(Пример структура: del1:del2:del3)*. За да се олесни ова форматирање, воведена е класата `DataPacket`. DataPacket всушност нуди функционалност за структурирање на пакетот во дадениот формат и негово деструктурирање, со цел да има стандарден начин како се праќа пакет, елиминирајќи ги грешките при форматирање.

 ## WPA2 4 Way Handshake
 
За да се воспостави конекција треба да се генерираат и изведат сите клучеви кои потоа ќе се користат во CCMP. Тоа се прави со 4 Way Handshake состоен од 4 пораки:

* Прва порака
	 - Клиентот добива барање да внеси password па тој пушта пакет кој содржи password,неговата MAC адреса и routerSSID. AP го добива овој пакет и проверува дали е точен добиениот password и routerSSID. Ако се точни, се генерира ANonce и се испраќа пакет кој го содржи АNonce.
	 
* Втора порака
  - Клиентот го прима пакетот и си генерира свој SNonce.
  - Сега клиентот ги има сите ресурси за да го генерира PTK(Pairwise Transient Key - се користи за енкрипција на комуникацијата).
  - Прво, се генерира PMK  (Pairwise Master Key), па со помош на PMK,ANonce,SNonce и MAC адресите на клиентот и AP се изведува PTK.
  - Потоа клиентот генерира MIC и го испраќа на AP заедно со SNonce.

* Трета порака
	- AP ја прима пораката од клиентот, па сега и тој ги има сите потребни ресурси за да си генерира свој PTK. 
  - Се генерира MIC и се проверува дали се совпаѓа со MIC на клиентот.
  - Ако се совпаѓа, се праќа генерираниот MIC на клиентот. (По правило тука се генерира и GTK(Group Transient Key) но тој се користи за broadcast i multicast па не е потребен во овој случај)

* Четврта порака
	- Клиентот го прима MIC од AP и исто го проверува дали се совпаѓа. Ако се совпаѓа, се отвара конекцијата и клиентот и AP може да продолжат со енкриптирана комуникација.
	
	
При успешно воспоставена конекција, секој пакет пратен помеѓу AP и Клиентот енкриптира, декриптира и автентицира со помош на CCMP имплементацијата.

## CCMP

Секоја порака пратена помеѓу Клиентот и AP е енкриптирана. Протокот на овие пораки е регулиран од класата `EncryptedNetworkContext`. Оваа класа е користена од AP и Клиентот, како заеднички интерфејс за праќање и енкриптирање, како и примање и декриптирање на пораки.

Енкрипцијата, декрипцијата и генерирањето на MIC се реализира со класата `CCMPImpl` 

Кога клиентот сака да пушти порака, текот е следен:

- Клиентот го инкрементира својот Packet Number (PN) и креира Nonce. Овој Nonce треба да е 128 битен за да се користи како влез во AES. Nonce'от се креира на следниот начин:
	- Се алоцира низа од бајти со должина 16 бајти, односно 128 бита. 
	- Првите 6 бајти се пополнуваат со PN.
  	- Вторите 6 бајти се пополнуваат со MAC адресата на клиентот.
  	- 13-тиот бајт се пополнува со QoS (Quality of Service).
- Во овој момент се повикува методот `encryptAndSendMessage` на инстанцата од класата `EncryptedNetworkContext` и се праќаат како аргументи nonce, и packetNumber.
  	- Во овој метод се генерира MIC и се енкриптира пораката, користејќи ги методите од класата `CCMPImpl`.
     - За да се генерира MIC се користи **AES-CBC**. За AES потребен е 128 битен иницијализациски вектор, односно досегашниот nonce. Но, досегашниот nonce засега е само 104 бита па се поставува падинг за да стане 128 бита. Енкрипицјата се прави со **AES-CTR**, во овој случај nonce се пополнува со нули.
     - Во пакетот што треба да се испрати, се поставуаат PN, енкриптираната порака заедно со енкриптираниот MIC.
       
  _Полесно е да се манипулира со стрингови од колку со бајти, затоа податоците што се испраќаат во пакетот што се во форма на бајти како MIC и пораката се кодираат во Base64_

- AP го прима пакетот, иги декодира потребните информации, и на ист начин, но во обратна насока извршува декрипција на пораката со помош на `EncryptedNetworkContext.recieveAndDecryptMessage` и `CCMPImpl.decrypt`, па генерира свој MIC на ист начин како клиентот.
- АP проверува дали неговиот MIC се совпаѓа со MIC на клиентот. Ако одговорот е да, интегритетот на пораката е зачуван и таа е успешно примена и се пушта повратна порака на клиентот.

> [!NOTE]
> Како клуч за AES алгоритмот се користи изведениот 48 бајтен клуч PTK. Toj всушност е збир од 3 клучеви: KCK, KEK, TK. Клучот ТК се користи во CCMP, во AES модовите на операција.

## 
*Ова е груба имплементација на WPA2 протоколот и CCM протоколот на повисоко ниво во Java, при што **не** се запазени сите детали во однос на податоците кои што се чуваат во пакетите, но претставува добра симулација на самиот тек на воспоставување конекција (4 way handshake) како и енкрипција,декрипција и проверка на интегритет на пораките.* ⚖️




