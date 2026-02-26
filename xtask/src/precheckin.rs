// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    crate::update_frozen_images::check_frozen_images()?;
    crate::clippy::clippy()?;
    Ok(())
}
