//
//  AbilitaCIE.cpp
//  cie-pkcs11
//
//  Created by ugo chirico on 06/10/18. http://www.ugochirico.com
//  Copyright © 2018 IPZS. All rights reserved.
//
#include <string.h>
#include "CSP/IAS.h"
#include "wintypes.h"
#include "PKCS11/PKCS11Functions.h"
#include "PKCS11/Slot.h"
#include "Util/ModuleInfo.h"
#include "Crypto/sha256.h"
#include "Crypto/sha512.h"
#include <functional>
#include "Crypto/ASNParser.h"
#include <string>
#include "CSP/AbilitaCIE.h"
#include <string>
#include "Cryptopp/misc.h"

#include "Crypto/ASNParser.h"
#include <stdio.h>
#include "Crypto/AES.h"
#include "Cryptopp/cryptlib.h"
#include "Cryptopp/asn.h"
#include "Util/CryptoppUtils.h"
#include "Sign/CIESign.h"
#include "Sign/CIEVerify.h"

#include <unistd.h>
#include <sys/socket.h>    //socket
#include <arpa/inet.h>    //inet_addr
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define ROLE_USER 				1
#define ROLE_ADMIN 				2
#define CARD_ALREADY_ENABLED	0x000000F0;

OID OID_SURNAME_CMD = ((OID(2) += 5) += 4) += 4;

OID OID_GIVENNAME_CMD = ((OID(2) += 5) += 4) += 42;

extern CModuleInfo moduleInfo;

void GetCertInfo(CryptoPP::BufferedTransformation & certin,
                 std::string & serial,
                 CryptoPP::BufferedTransformation & issuer,
                 CryptoPP::BufferedTransformation & subject,
                 std::string & notBefore,
                 std::string & notAfter,
                 CryptoPP::Integer& mod,
                 CryptoPP::Integer& pubExp);

DWORD CardAuthenticateEx(IAS*       ias,
                        DWORD       PinId,
                        DWORD       dwFlags,
                        BYTE*       pbPinData,
                        DWORD       cbPinData,
                        BYTE*       *ppbSessionPin,
                        DWORD*      pcbSessionPin);

int main(int argc, char **argv)
{
    char* readers = NULL;
    char* ATR = NULL;

    if (argc != 2) {
	printf("\n\nUso: ./abilitacie PIN\n");
	return 0;
    }

    const char* szPIN = argv[1];

    // verifica bontà PIN
    if(szPIN == NULL || strnlen(szPIN, 9) != 8)
    {
    	return CKR_PIN_LEN_RANGE;
    }

	size_t i = 0;
	while (i < 8 && (szPIN[i] >= '0' && szPIN[i] <= '9'))
		i++;

	if (i != 8)
		return CKR_PIN_INVALID;

	try
    {
		std::map<uint8_t, ByteDynArray> hashSet;
		
		DWORD len = 0;
		ByteDynArray CertCIE;
		ByteDynArray SOD;
		ByteDynArray IdServizi;
		
		SCARDCONTEXT hSC;

        printf("Connessione alla CIE\n");
        
		long nRet = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &hSC);
        if(nRet != SCARD_S_SUCCESS)
            return CKR_DEVICE_ERROR;
        
        if (SCardListReaders(hSC, nullptr, NULL, &len) != SCARD_S_SUCCESS) {
            return CKR_TOKEN_NOT_PRESENT;
        }
        
        readers = (char*)malloc(len);
        
        if (SCardListReaders(hSC, nullptr, (char*)readers, &len) != SCARD_S_SUCCESS) {
            free(readers);
            return CKR_TOKEN_NOT_PRESENT;
        }

        printf("CIE Connessa\n");
        
		char *curreader = readers;
		bool foundCIE = false;
		for (; curreader[0] != 0; curreader += strnlen(curreader, len) + 1)
        {
            safeConnection conn(hSC, curreader, SCARD_SHARE_SHARED);
            if (!conn.hCard)
                continue;

            DWORD atrLen = 40;
            if(SCardGetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, (uint8_t*)ATR, &atrLen) != SCARD_S_SUCCESS) {
                free(readers);
                return CKR_DEVICE_ERROR;
            }
            
            ATR = (char*)malloc(atrLen);
            
            if(SCardGetAttrib(conn.hCard, SCARD_ATTR_ATR_STRING, (uint8_t*)ATR, &atrLen) != SCARD_S_SUCCESS) {
                free(readers);
                free(ATR);
                return CKR_DEVICE_ERROR;
            }
            
            ByteArray atrBa((BYTE*)ATR, atrLen);
            

            printf("Verifica carta esistente\n");

            IAS ias((CToken::TokenTransmitCallback)TokenTransmitCallback, atrBa);
            ias.SetCardContext(&conn);
            
            foundCIE = false;
            
            ias.token.Reset();
            ias.SelectAID_IAS();
            ias.ReadPAN();
        
            
            ByteDynArray IntAuth;
            ias.SelectAID_CIE();
            ias.ReadDappPubKey(IntAuth);
            //ias.SelectAID_CIE();
            ias.InitEncKey();
            
            ByteDynArray IdServizi;
            ias.ReadIdServizi(IdServizi);

            if (ias.IsEnrolled())
            {
                return CARD_ALREADY_ENABLED;
            }


            printf("Lettura dati dalla CIE\n");
        
            ByteArray serviziData(IdServizi.left(12));

            ByteDynArray SOD;
            ias.ReadSOD(SOD);
            uint8_t digest = ias.GetSODDigestAlg(SOD);
                        
            ByteArray intAuthData(IntAuth.left(GetASN1DataLenght(IntAuth)));
            
			ByteDynArray IntAuthServizi;
            ias.ReadServiziPubKey(IntAuthServizi);
            ByteArray intAuthServiziData(IntAuthServizi.left(GetASN1DataLenght(IntAuthServizi)));

            ias.SelectAID_IAS();
            ByteDynArray DH;
            ias.ReadDH(DH);
            ByteArray dhData(DH.left(GetASN1DataLenght(DH)));

            // poichè la CIE abilitata sul desktop può essere solo una, szPAN passato da CIEID è sempre null
//            if (szPAN && IdServizi != ByteArray((uint8_t*)szPAN, strnlen(szPAN, 20)))
//                continue;

            foundCIE = true;
            
            printf("Autenticazione...\n");
            
            free(readers);
            readers = NULL;
            free(ATR);
            ATR = NULL;

            DWORD rs = CardAuthenticateEx(&ias, ROLE_USER, FULL_PIN, (BYTE*)szPIN, (DWORD)strnlen(szPIN, sizeof(szPIN)), nullptr, 0);
            if (rs == SCARD_W_WRONG_CHV)
            {
                return CKR_PIN_INCORRECT;
            }
            else if (rs == SCARD_W_CHV_BLOCKED)
            {
                return CKR_PIN_LOCKED;
            }
            else if (rs != SCARD_S_SUCCESS)
            {
                return CKR_GENERAL_ERROR;
            }
            
            
            printf("Lettura seriale\n");
            
            ByteDynArray Serial;
            ias.ReadSerialeCIE(Serial);
            ByteArray serialData = Serial.left(9);
            std::string st_serial((char*)serialData.data(), serialData.size());
            printf("\nserial data: %s\n", st_serial.c_str());

            
            printf("Lettura certificato\n");
            
            ByteDynArray CertCIE;
            ias.ReadCertCIE(CertCIE);
            ByteArray certCIEData = CertCIE.left(GetASN1DataLenght(CertCIE));
            
            if (digest == 1)
            {
                CSHA256 sha256;
                hashSet[0xa1] = sha256.Digest(serviziData);
                hashSet[0xa4] = sha256.Digest(intAuthData);
                hashSet[0xa5] = sha256.Digest(intAuthServiziData);
                hashSet[0x1b] = sha256.Digest(dhData);
                hashSet[0xa2] = sha256.Digest(serialData);
                hashSet[0xa3] = sha256.Digest(certCIEData);
                ias.VerificaSOD(SOD, hashSet);

            }
            else
            {
                CSHA512 sha512;
                hashSet[0xa1] = sha512.Digest(serviziData);
                hashSet[0xa4] = sha512.Digest(intAuthData);
                hashSet[0xa5] = sha512.Digest(intAuthServiziData);
                hashSet[0x1b] = sha512.Digest(dhData);
                hashSet[0xa2] = sha512.Digest(serialData);
                hashSet[0xa3] = sha512.Digest(certCIEData);
                ias.VerificaSODPSS(SOD, hashSet);
            }

            ByteArray pinBa((uint8_t*)szPIN, 4);
            
            printf("Memorizzazione in cache\n");
            
            std::string sidServizi((char*)IdServizi.data(), IdServizi.size());

            ias.SetCache((char*)sidServizi.c_str(), CertCIE, pinBa);
            
            std::string span((char*)sidServizi.c_str());
            std::string name;
            std::string surname;
            
            CryptoPP::ByteQueue certin;
            certin.Put(CertCIE.data(),CertCIE.size());
            
            std::string serial;
            CryptoPP::ByteQueue issuer;
            CryptoPP::ByteQueue subject;
            std::string notBefore;
            std::string notAfter;
            CryptoPP::Integer mod;
            CryptoPP::Integer pubExp;
            
            GetCertInfo(certin, serial, issuer, subject, notBefore, notAfter, mod, pubExp);
            
            CryptoPP::BERSequenceDecoder subjectEncoder(subject);
            {
                while(!subjectEncoder.EndReached())
                {
                    CryptoPP::BERSetDecoder item(subjectEncoder);
                    CryptoPP::BERSequenceDecoder attributes(item); {
                        
                        OID oid(attributes);
                        if(oid == OID_GIVENNAME_CMD)
                        {
                            byte tag = 0;
                            attributes.Peek(tag);
                            
                            CryptoPP::BERDecodeTextString(
                                                          attributes,
                                                          name,
                                                          tag);
                        }
                        else if(oid == OID_SURNAME_CMD)
                        {
                            byte tag = 0;
                            attributes.Peek(tag);
                            
                            CryptoPP::BERDecodeTextString(
                                                          attributes,
                                                          surname,
                                                          tag);
                        }
                        
                        item.SkipAll();
                    }
                }
            }
        
            subjectEncoder.SkipAll();
            
            std::string fullname = name + " " + surname;
            printf(span.c_str(), fullname.c_str(), st_serial.c_str());
		}
        
		if (!foundCIE) {
            return CKR_TOKEN_NOT_RECOGNIZED;
            
		}

	}
	catch (std::exception &ex) {
	    printf("Exception: %s\n",ex.what());
        if(ATR)
            free(ATR);
        
        if(readers)
            free(readers);
        return CKR_GENERAL_ERROR;
	}

    if(ATR)
        free(ATR);
    if(readers)
    	free(readers);
    
    return SCARD_S_SUCCESS;
}



DWORD CardAuthenticateEx(IAS*       ias,
                         DWORD       PinId,
                         DWORD       dwFlags,
                         BYTE*       pbPinData,
                         DWORD       cbPinData,
                         BYTE*       *ppbSessionPin,
                         DWORD*      pcbSessionPin) {
    
    printf("selected CIE applet\n");
    ias->SelectAID_IAS();
    ias->SelectAID_CIE();
    
    

    printf("init DH Param\n");
    // leggo i parametri di dominio DH e della chiave di extauth
    ias->InitDHParam();
    

    printf("read DappPubKey\n");

    ByteDynArray dappData;
    ias->ReadDappPubKey(dappData);
    
    printf("InitExtAuthKeyParam\n");
    ias->InitExtAuthKeyParam();
    
    printf("DHKeyExchange\n");
    ias->DHKeyExchange();

    printf("DAPP\n");

    // DAPP
    ias->DAPP();
    
    printf("VerifyPIN\n");

    // verifica PIN
    StatusWord sw;
    if (PinId == ROLE_USER) {
        
        ByteDynArray PIN;
        if ((dwFlags & FULL_PIN) != FULL_PIN)
            ias->GetFirstPIN(PIN);
        PIN.append(ByteArray(pbPinData, cbPinData));
        sw = ias->VerifyPIN(PIN);
    }
    else if (PinId == ROLE_ADMIN) {
        ByteArray pinBa(pbPinData, cbPinData);
        sw = ias->VerifyPUK(pinBa);
    }
    else
        return SCARD_E_INVALID_PARAMETER;
    
    printf("verifyPIN ok\n");

    if (sw == 0x6983) {
        if (PinId == ROLE_USER)
        {
            printf("PIN Bloccato\n");
            ias->IconaSbloccoPIN();
        }

        return SCARD_W_CHV_BLOCKED;
    }
    else if (sw >= 0x63C0 && sw <= 0x63CF) {
        printf("PIN Errato. Tentativi rimanenti: %d\n",sw - 0x63C0);
        return SCARD_W_WRONG_CHV;
    }
    else if (sw == 0x6700) {
    	printf("PIN Errato\n");
        return SCARD_W_WRONG_CHV;
    }
    else if (sw == 0x6300)
    {
    	printf("PIN Errato\n");
        return SCARD_W_WRONG_CHV;
    }
    else if (sw != 0x9000) {
    	printf("Errore smart card\n");
        throw scard_error(sw);
    }
    
    printf("VerifyPIN OK\n");

    return SCARD_S_SUCCESS;
}
