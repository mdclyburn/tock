/*! Provide ISLE configuration for applications.
 */

use capsules_extra::isle::{
    Realm,
    ISLEConfigurationProvider,
};

pub struct Fixed;

impl ISLEConfigurationProvider for Fixed {
    fn init_context(
        &self,
        realm_ctxs: &mut [Realm])
    {
        realm_ctxs[0].init(
            0x1ef2,
            &[
                0xad, 0x22, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            &[
                0x2f, 0x75, 0x27, 0x4e,
                0x2f, 0x75, 0x27, 0x4e,
            ]);

        realm_ctxs[0].set_realm_id(0x5AFE);
        realm_ctxs[0].set_network_no(
            &[0xEA, 0xA9, 0x34, 0x52, 0x0A, 0x1B]);
    }
}

pub struct FICRBasedIID {
    device_addr: [u8; 6],
    realm_id: u16,
}

impl FICRBasedIID {
    pub unsafe fn new(realm_id: u16) -> FICRBasedIID {
        let ficr: *const [u8; 6] = (0x1000_0000 + 0x00A4) as *const [u8; 6];
        let device_addr = *ficr;

        FICRBasedIID {
            device_addr,
            realm_id,
        }
    }
}

impl ISLEConfigurationProvider for FICRBasedIID {
    fn init_context(
        &self,
        realm_ctxs: &mut [Realm])
    {
        let master_secret: [u8; _] = [
            0xad, 0x22, 0x00, 0x00,
            0xad, 0x22, 0x00, 0x00,
            0xad, 0x22, 0x00, 0x00,
            0xad, 0x22, 0x00, 0x00,
        ];
        let master_salt: [u8; _] = [
            0x12, 0x34, 0x00, 0x00,
            0x12, 0x34, 0x00, 0x00,
        ];

        realm_ctxs[0].init(self.realm_id, &master_secret, &master_salt);
        realm_ctxs[0].set_network_no(&self.device_addr);
    }
}
