/*! Provide ISLE configuration for applications.
 */

use capsules_extra::isle::{
    GroupOSCOREContext,
    ISLEConfigurationProvider,
};

pub struct Fixed;

impl ISLEConfigurationProvider for Fixed {
    fn init_context(
        &self,
        context: &mut [GroupOSCOREContext])
    {
        context[0].init(
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

        context[0].set_realm_id(0x5AFE);
        context[0].set_network_no(
            &[0xEA, 0xA9, 0x34, 0x52, 0x0A, 0x1B]);
    }
}
