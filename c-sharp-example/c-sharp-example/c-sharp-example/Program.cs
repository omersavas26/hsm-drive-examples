using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

Pkcs11InteropFactories factory = new Pkcs11InteropFactories();

string path = @"C:\SoftHSM2\lib\softhsm2-x64.dll";
IPkcs11Library lib = factory.Pkcs11LibraryFactory.LoadPkcs11Library(factory, path, AppType.MultiThreaded);

Console.WriteLine("load lib OK");


ulong slotId = 577229486;
string pin = "9999";

List<ISlot> slots = lib.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
ISlot slot = null;
foreach (var item in slots)
{
    if (item.SlotId != slotId) continue;
    
    slot = item; 
    break;
}

if (slot == null) throw new Exception("Slot not found in hsm");

ISession session = slot.OpenSession(SessionType.ReadWrite);
session.Login(CKU.CKU_USER, pin);

Console.WriteLine("slot login OK");


string keyLabel = "aes128";

List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel));

session.FindObjectsInit(objectAttributes);
List<IObjectHandle> foundObjects = session.FindObjects(1);
session.FindObjectsFinal();
if (foundObjects.Count == 0) throw new Exception("Key Not Found");

IObjectHandle key = foundObjects[0];

byte[] iv = new byte[16];
IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_CBC_PAD, iv);
byte[] sourceData = ConvertUtils.Utf8StringToBytes("99999999999999999999999999999999");

byte[] encryptedData = session.Encrypt(mechanism, key, sourceData);
Console.WriteLine("Encrypt OK: " + encryptedData.Length);

byte[] decryptedData = session.Decrypt(mechanism, key, encryptedData);
Console.WriteLine("Decrypt OK: " + System.Text.Encoding.Default.GetString(decryptedData));