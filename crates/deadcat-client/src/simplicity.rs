use simplex::simplicityhl::simplicity::jet::Elements;
use simplex::simplicityhl::simplicity::{BitIter, RedeemNode};

pub(crate) fn ensure_budget(mut stack: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, String> {
    if stack.len() != 4 {
        return Err(format!(
            "expected four finalized Simplicity stack elements, got {}",
            stack.len()
        ));
    }
    let redeem = RedeemNode::<Elements>::decode(
        BitIter::from(stack[1].iter().copied()),
        BitIter::from(stack[0].iter().copied()),
    )
    .map_err(|error| format!("failed to decode finalized Simplicity program: {error:?}"))?;
    let cost = redeem.bounds().cost;
    if !cost.is_budget_valid(&stack) {
        let padding = cost.get_padding(&stack).ok_or_else(|| {
            format!(
                "Simplicity stack is underbudget for execution cost {cost} and cannot be padded"
            )
        })?;
        stack.push(padding);
    }
    if !cost.is_budget_valid(&stack) {
        return Err(format!(
            "Simplicity stack remains underbudget for execution cost {cost} after padding"
        ));
    }
    Ok(stack)
}
