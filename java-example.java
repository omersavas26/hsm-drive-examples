/// Merhaba sevigli takipçi. Bu kodu daha malesef deneyemedim. Denediğimde sonuçları ile paylaşacağım.

try {
            final String name = "testAes";
            final String library = "C:\\ProCrypt-KM3000\\config\\procryptoki.dll";

            final String slot = "0";
            final char[] slotPIN = {'1', '1', '1', '1'};

            System.out.println(System.getProperty("java.library.path"));
//            System.setProperty("java.library.path", "D:\\Projeler\\JavaProjeleri\\HSMProcenne\\ProcenneLib");
//            System.out.println(System.getProperty("java.library.path"));
            //System.loadLibrary("procryptoki");

            //System.loadLibrary(library);

            StringBuilder builder = new StringBuilder();
            builder.append("name=" + name);
            builder.append(System.getProperty("line.separator"));
            builder.append("library=\"" + library + "\"");
            builder.append(System.getProperty("line.separator"));
            builder.append("slot=" + slot);

            String gonderilenCumle = builder.toString().replace("\\", "\\\\");

            ByteArrayInputStream bais = new ByteArrayInputStream(gonderilenCumle.getBytes());
            Provider provider = new sun.security.pkcs11.SunPKCS11(bais);
            provider.setProperty("pkcs11LibraryPath", library);
            Security.addProvider(provider);

            PKCS11 pkcs11Nesnesi = PKCS11.getInstance(((sun.security.pkcs11.SunPKCS11) provider).getProperty("pkcs11LibraryPath"), null, null, true);

            // get cryptoki information
            CK_INFO info = pkcs11Nesnesi.C_GetInfo();

            System.out.println("manufacturerID: " + String.valueOf(info.manufacturerID));
            System.out.println("libraryDescription: " + String.valueOf(info.libraryDescription));
            System.out.println("libraryVersion: " + String.valueOf(info.libraryVersion));

            long [] slotListesi = pkcs11Nesnesi.C_GetSlotList(true);
            System.out.println("Slot sayımız: " + slotListesi.length);
            for (long l : slotListesi) {
                System.out.println(String.format("%s. slot ", l ));
            }

            //pkcs11Nesnesi.notify();

            long hSession = pkcs11Nesnesi.C_OpenSession(Integer.parseInt(slot), PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            System.out.println("C_OpenSession: " + hSession);

            CK_SESSION_INFO infoSession = pkcs11Nesnesi.C_GetSessionInfo(hSession);
            System.out.println("CK_SESSION_INFO flags: " + infoSession.flags);
            System.out.println("CK_SESSION_INFO slotID: " + infoSession.slotID);
            System.out.println("CK_SESSION_INFO state: " + infoSession.state);
            System.out.println("CK_SESSION_INFO u1DeviceError: " + infoSession.ulDeviceError);

            // enter the slot pin
            pkcs11Nesnesi.C_Login(hSession, PKCS11Constants.CKU_USER, slotPIN);


            // Get 256 bytes of RNG
            byte[] rngBytes = new byte[256];
            pkcs11Nesnesi.C_GenerateRandom(hSession, rngBytes);
            System.out.println("===RandomBytes===");
            System.out.println(byteArrayToHex(rngBytes));

            // AES encryption
            // find key handle
            CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[1];
            template[0] = new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, "testAes");
            //template[0] = new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE, "395D9B6C1A3FF6D5FB76981E1051C53A");
            pkcs11Nesnesi.C_FindObjectsInit(hSession, template);
            long[] hObjs = pkcs11Nesnesi.C_FindObjects(hSession, 1);

            if (hObjs.length == 0) {
                System.out.println("Key object not found");
            } else {

                // AES encryption
                CK_MECHANISM mech = new CK_MECHANISM(PKCS11Constants.CKM_AES_ECB);
                pkcs11Nesnesi.C_EncryptInit(hSession, mech, hObjs[0]);

                // Encrypt generated rng bytes for example
                byte ecnryptedBytes[] = new byte[256];

/*
                long hSession,      hSession
                long directIn,
                byte[] in,          rngBytes
                int inOfs,          0
                int inLen,          rngBytes.length
                long directOut,
                byte[] out,         ecnryptedBytes
                int outOfs,         0
                int outLen          ecnryptedBytes.length*/

                int respEnc = pkcs11Nesnesi.C_Encrypt(hSession, 0, rngBytes, 0, rngBytes.length, 0, ecnryptedBytes, 0, ecnryptedBytes.length);

                System.out.println("Encrypt Response : " + respEnc);

                System.out.println("===EncryptedBytes===");
                System.out.println(byteArrayToHex(ecnryptedBytes));



                pkcs11Nesnesi.C_DecryptInit(hSession, mech, hObjs[0]);

                byte decryptedBytes[] = new byte[256];

                int respDec = pkcs11Nesnesi.C_Decrypt(hSession, 0, ecnryptedBytes, 0, ecnryptedBytes.length, 0 , decryptedBytes, 0, decryptedBytes.length);

                System.out.println("Decrypt Response : " + respDec);
                System.out.println("===DecryptedBytes===");
                System.out.println(byteArrayToHex(decryptedBytes));


                pkcs11Nesnesi.C_CloseSession(hSession);
            }

            pkcs11Nesnesi.C_Finalize(PKCS11Constants.NULL_PTR);

        } catch (Exception e) {
            System.out.println("hata");
            e.printStackTrace();
        }
