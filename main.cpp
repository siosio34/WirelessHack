#include <QCoreApplication>
#include <ieee80211_radiotap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <math.h>
#include <pcap-namedb.h>
#include <iostream>
using namespace std;

bool prflag[32]= {false};
int radiotap_len = 0;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void radiotap_present_bit_check(u_int32_t present_flags, ieee80211_radiotap_type type);
void Radiotap_Content(const u_char *buffer);
int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 23";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */


    int num;
    int i = 0;

    // DEVICE lIST 검색
    if (pcap_findalldevs(&alldevs,errbuf) == PCAP_ERROR)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
           if (d->description)
               printf(" (%s)\n", d->description);
           else
               printf(" (No description available)\n");
    }

    if (i == 0)
        {
                printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
                return -1;
        }

    printf("Enter the interface number (1-%d):", i);
    cin >> num;

    if (num < 1 || num > i)
    {
        printf("\nInterface number out of range.\n");
         /* Free the device list */
        pcap_freealldevs(alldevs);
       return -1;
    }

    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(d->name, 65536, 1, -1, errbuf);
     if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }


    // sniff loop

    pcap_loop(handle, -1, process_packet , NULL);

    return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    hex(cout);

    if(buffer[0] == 0 && buffer[1] == 0) // version & pad 0 -> wireless Packet
    {
     struct ieee80211_radiotap_header *hdr = (struct ieee80211_radiotap_header *)buffer;

     cout << "----------------Radio Tab Header---------------"<<endl;
     cout << "Header revision: " << (int)hdr->it_version << endl;
     cout << "Header pad     : " << (int)hdr->it_pad <<endl;
     cout << "Header length  : " << ntohs(hdr->it_len) <<endl;
     cout << "Present flags  : " << ntohl(hdr->it_present) <<endl;
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_TSFT);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_FLAGS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_RATE);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_CHANNEL);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_FHSS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DBM_ANTNOISE);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_LOCK_QUALITY);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_TX_ATTENUATION);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DB_TX_ATTENUATION);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DBM_TX_POWER);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_ANTENNA);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DB_ANTSIGNAL);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DB_ANTNOISE);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_RX_FLAGS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_TX_FLAGS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_RTS_RETRIES);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_DATA_RETRIES);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_MCS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_AMPDU_STATUS);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_VHT);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_VENDOR_NAMESPACE);
     radiotap_present_bit_check(hdr->it_present,IEEE80211_RADIOTAP_EXT);
     \
     radiotap_len += sizeof(__le64);

     Radiotap_Content(buffer);

     radiotap_len = 0;

    }

}

void radiotap_present_bit_check(u_int32_t present_flags, ieee80211_radiotap_type type)
{
        int mask = 1;
        string check_str;
        check_str = (present_flags & (mask << type) ? "TRUE":"FALSE");

        if(check_str == "TRUE")
        {
           prflag[type] = true;
        }

        switch (type) {
        case IEEE80211_RADIOTAP_TSFT:
           cout << " > TSFT: "<<check_str <<endl;
           break;
        case IEEE80211_RADIOTAP_FLAGS:
           cout << " > Flags: "<<check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_RATE:
            cout << " > Rate: "<<check_str<<endl;
            break;
        case IEEE80211_RADIOTAP_CHANNEL:
            cout << " > Channel: "<<check_str<<endl;
            break;
        case IEEE80211_RADIOTAP_FHSS:
            cout << " > FHSS: "<<check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            cout << " > dBm Antenna Signal: "<<check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            cout << " > dBm Antenna Noise: "<< check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_LOCK_QUALITY:
            cout << " > Lock Quality: " <<check_str << endl;
            break;
        case IEEE80211_RADIOTAP_TX_ATTENUATION:
            cout << " > TX Attenuation: "<< check_str << endl;
            break;
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
            cout << " > dB TX Attenuation: "<< check_str<<endl;
            break;
        case IEEE80211_RADIOTAP_DBM_TX_POWER:
            cout << " > dBm TX Power: "<< check_str << endl;
            break;
        case IEEE80211_RADIOTAP_ANTENNA:
            cout << " > Antenna: "<<check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            cout << " > dB Antenna Signal: "<<check_str<< endl;
            break;
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
            cout << " > dB Antenna Noise: "<<check_str<<endl;
            break;

         // these is ///////////////////////////////////

        case IEEE80211_RADIOTAP_RX_FLAGS:
            cout << " > RX flags: "<< check_str <<endl;
            break;

        case IEEE80211_RADIOTAP_TX_FLAGS: // ?
            cout << " > TX flags: " << check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_RTS_RETRIES: // ?
            cout <<" > HT information: "<< check_str<<endl;
            break;
        case IEEE80211_RADIOTAP_DATA_RETRIES: // ?
            cout <<" > DATA_RETRIES: "<< check_str <<endl;
            break;

        // //////////////////////////////////////////////
        case IEEE80211_RADIOTAP_MCS: //
            cout <<" > HT information:: " << check_str <<endl;
            break;

        case IEEE80211_RADIOTAP_AMPDU_STATUS:
            cout <<" > A-MPDU Status: "<< check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_VHT:
            cout <<" > VHT information: " << check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
            cout << " > Radiotap NS next: "<< check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
            cout <<" > Vendor NS next: " << check_str <<endl;
            break;
        case IEEE80211_RADIOTAP_EXT:
            cout <<" > Exit: "<<check_str<<endl;
            break;

        }

}

void Radiotap_Content(const u_char *buffer)
{
    if(prflag[IEEE80211_RADIOTAP_TSFT]) // TSTF  ON
    {
        __le64 microseconds;
        memcpy(&microseconds,buffer+radiotap_len,sizeof(__le64));
        radiotap_len += sizeof(__le64);
        cout << "microseconds: " <<" "<< microseconds << endl;

    }
    if(prflag[IEEE80211_RADIOTAP_FLAGS]) // FLAGS ON
    {
        __u8 _flags;
        memcpy(&_flags,buffer+radiotap_len,sizeof(__u8));
        cout << "Flags: 0x" << (int)_flags <<endl;
        radiotap_len += sizeof(__u8);

        int mask = 1;
        string flags_check;
        for(int i =0 ; i <8 ; i++)
        {
            float j = pow(2.0,(float)i);
            flags_check = (_flags & (mask << (i)) ? "True":"False");

            switch((int)j) {
            case IEEE80211_RADIOTAP_F_CFP:
                    cout << " > CTP: "<< flags_check << endl;
                    break;
            case IEEE80211_RADIOTAP_F_SHORTPRE:
                    if(flags_check == "True") cout << " > Preamble: " << "Short" << endl;
                    else cout << " > Preamble: " << "Long"  << endl;
                    break;
            case IEEE80211_RADIOTAP_F_WEP:
                    cout <<" > WEP: " << flags_check << endl;
                    break;
            case IEEE80211_RADIOTAP_F_FRAG:
                cout << " > Fragmentation: " << flags_check << endl;
                break;
            case IEEE80211_RADIOTAP_F_FCS:
                cout << " > FCS at end: " << flags_check << endl;
                break;
            case IEEE80211_RADIOTAP_F_DATAPAD:
                cout << " > Data Pad: "<<flags_check << endl;
                break;
            case IEEE80211_RADIOTAP_F_BADFCS:
                cout << " > Bad FCS: "<<flags_check << endl;
                break;
            case IEEE80211_RADIOTAP_F_Short_GI:
                cout << " > Short GI "<<flags_check << endl;
                break;
            }
        }

    }

    if(prflag[IEEE80211_RADIOTAP_RATE]) {

        __u8 radio_rate;
        memcpy(&radio_rate,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << "Rate: " << ((float)radio_rate * 5) / 10 <<".0 Mb/s" <<endl;
    }

    if(prflag[IEEE80211_RADIOTAP_CHANNEL]) {
        __le16 chn_frequency, chn_type;
        memcpy(&chn_frequency,buffer+radiotap_len,sizeof(__le16)); // channel frequency
        radiotap_len += sizeof(__le16);

        memcpy(&chn_type,buffer+radiotap_len,sizeof(__le16)); //channel type
        radiotap_len += sizeof(__le16);

        cout << "Channel Frequency: 0x"<<(int)(ntohs(chn_frequency)) <<endl;
        cout << "Channel Type: 0x"<<(int)(ntohs(chn_type)) << endl;

        int mask = 32;
        string flags_check;
        for(int i =0 ; i <12 ; i++)
        {
            float j = pow(2.0,(float)(i+4));
            flags_check = (chn_type & (mask << (i)) ? "True":"False");

            switch((int)j) {

            case IEEE80211_CHAN_TURBO:
                cout <<" > Turbo: "<<flags_check<<endl;
                break;
            case IEEE80211_CHAN_CCK:
                cout <<" > Complementary Code Keying(CCK): " << flags_check<<endl;
                break;
            case IEEE80211_CHAN_OFDM:
                cout <<" > Orthogonal Frequency-Division Multiplexing (OFDM):"<<flags_check << endl;
                break;
            case IEEE80211_CHAN_2GHZ:
                cout <<" > 2 Ghz spectrum: " <<flags_check << endl;
                break;
            case IEEE80211_CHAN_5GHZ:
                cout << " > 5 GHz spectrum: " << flags_check << endl;
                break;
            case IEEE80211_CHAN_PASSIVE:
                cout << " > Passive: " << flags_check << endl;
                break;
            case IEEE80211_CHAN_DYN:
                cout << " > Dynamic CCK-OFDM: "<< flags_check << endl;
                break;
            case IEEE80211_CHAN_GFSK:
                cout << " > Gaussian Frequency Sift Keying (GFSK): " << flags_check << endl;
                break;
            case IEEE80211_CHAN_GSM:
                cout << " > GSM: " << flags_check << endl;
                break;
            case IEEE80211_CHAN_STURBO:
                cout << " > Static Turbo: " << flags_check << endl;
                break;
            case IEEE80211_CHAN_HALF:
                cout << " > Half Rate Channel: " << flags_check << endl;
                break;
            case IEEE80211_CHAN_QUARTER:
                cout << " > Quarter Rate Channel: " << flags_check << endl;
                break;


            }
        }
    }

    if(prflag[IEEE80211_RADIOTAP_FHSS])
    {
        __le16 hs_pt; // first_byte-hop_set second byte - pattern

        memcpy(&hs_pt,buffer+radiotap_len,sizeof(__le16)); // channel frequency
        radiotap_len += sizeof(__le16);

        cout << " hop set and pattern: 0x"<<(int)ntohs(hs_pt) << endl;

    }

    if(prflag[IEEE80211_RADIOTAP_DBM_ANTSIGNAL])
    {
        // RF signal power at the antenna, decibel difference from  one milliwatt.

        __s8 _dBm;
        memcpy(&_dBm,buffer+radiotap_len,sizeof(__s8));
        radiotap_len += sizeof(__s8);
         cout << " SSI Signal: 0x"<<(int)_dBm << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_DBM_ANTNOISE])
    {
        // RF noise power at the antenna, decibel difference from one milliwatt.

        __s8 _dBm2;
        memcpy(&_dBm2,buffer+radiotap_len,sizeof(__s8));
        radiotap_len += sizeof(__s8);
        cout << "Decibels from one milliwatt: 0x"<<(int)_dBm2 << endl;

    }
    if(prflag[IEEE80211_RADIOTAP_LOCK_QUALITY]){
        __le16 _unitless;
        memcpy(&_unitless,buffer+radiotap_len,sizeof(__le16));
        radiotap_len += sizeof(__le16);
        cout << "Signal Quality: 0x"<<(int)_unitless << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_TX_ATTENUATION]){
        __le16 _unitless2;
        memcpy(&_unitless2,buffer+radiotap_len,sizeof(__le16));
        radiotap_len += sizeof(__le16);
        cout << "Transmit Power as unitless: 0x"<<(int)_unitless2 << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_DB_TX_ATTENUATION]){
        __le16 _decibel;
        memcpy(&_decibel,buffer+radiotap_len,sizeof(__le16));
        radiotap_len += sizeof(__le16);
        cout << "Transmit Power as decibel: 0x"<<(int)_decibel << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_DBM_TX_POWER]){
        __s8 _dBm3;
        memcpy(&_dBm3,buffer+radiotap_len,sizeof(__s8));
        radiotap_len += sizeof(__s8);
        cout << "Transmit Power as dBm: 0x"<<(int)_dBm3 << endl;

    }
    if(prflag[IEEE80211_RADIOTAP_ANTENNA]){
        __u8 _atenna;
        memcpy(&_atenna,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << "Antenna: 0x"<<(int)_atenna << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_DB_ANTSIGNAL]){
        __u8 signal_dB; // RF signal power
        memcpy(&signal_dB,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << "RF signal power at the antenna: 0x"<<(int)signal_dB << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_DB_ANTNOISE]){
        __u8 noise_db; // RF noise power
        memcpy(&noise_db,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << " RF noise power at the antenna: 0x"<<(int)noise_db << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_RX_FLAGS]){
        __le16 _rxflags;
        memcpy(&_rxflags,buffer+radiotap_len,sizeof(__le16));
        radiotap_len += sizeof(__le16);
        cout << "RX Flags: 0x"<<(int)(ntohs(_rxflags)) << endl;

    }

    if(prflag[IEEE80211_RADIOTAP_TX_FLAGS]){
        __le16 _txflags;
        memcpy(&_txflags,buffer+radiotap_len,sizeof(__le16));
        radiotap_len += sizeof(__le16);
        cout << "TX Flags: 0x"<<(int)(ntohs(_txflags)) << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_RTS_RETRIES]){
        __u8 _rts_retries;
        memcpy(&_rts_retries,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << "_rts_retries count: 0x"<<(int)_rts_retries << endl;

    }

    if(prflag[IEEE80211_RADIOTAP_DATA_RETRIES]){
        __u8 _unicast_retries;
        memcpy(&_unicast_retries,buffer+radiotap_len,sizeof(__u8));
        radiotap_len += sizeof(__u8);
        cout << "_unicast_retries Num: 0x"<<(int)_unicast_retries << endl;
    }

    if(prflag[IEEE80211_RADIOTAP_MCS]){

    }
    if(prflag[IEEE80211_RADIOTAP_AMPDU_STATUS]){}
    if(prflag[IEEE80211_RADIOTAP_VHT]){}

    if(prflag[IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE]){}
    if(prflag[IEEE80211_RADIOTAP_VENDOR_NAMESPACE]){}
    if(prflag[IEEE80211_RADIOTAP_EXT]){}


}


