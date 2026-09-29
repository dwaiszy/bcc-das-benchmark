//! Shared deterministic grouping primitives for non-scalar opening profiles.

use super::{GroupLayout, LocalPosition};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId {
    pub local_code_index: usize,
    pub local_group_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalGroup {
    pub id: GroupId,
    pub local_positions: Vec<usize>,
}

pub fn validate_group_size(group_size: usize) -> Result<(), &'static str> {
    if group_size == 0 {
        Err("group_size must be greater than zero")
    } else {
        Ok(())
    }
}

pub fn contiguous_groups(
    local_code_index: usize,
    local_len: usize,
    group_size: usize,
) -> Vec<LocalGroup> {
    validate_group_size(group_size).expect("validated protocol group size");
    (0..local_len)
        .step_by(group_size)
        .enumerate()
        .map(|(local_group_index, start)| LocalGroup {
            id: GroupId {
                local_code_index,
                local_group_index,
            },
            local_positions: (start..(start + group_size).min(local_len)).collect(),
        })
        .collect()
}

pub fn group_for_local_index(
    local_code_index: usize,
    local_index: usize,
    group_size: usize,
) -> GroupId {
    GroupId {
        local_code_index,
        local_group_index: local_index / group_size,
    }
}

pub fn layout_name(layout: GroupLayout) -> &'static str {
    match layout {
        GroupLayout::ContiguousLocal => "contiguous-local",
        GroupLayout::EvaluationCoset => "evaluation-coset",
    }
}

pub fn local_position_in_group(group: &LocalGroup, position: LocalPosition) -> bool {
    group.id.local_code_index == position.local_code().get()
        && group.local_positions.contains(&position.local_index())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_groups_partition_partial_tail() {
        let groups = contiguous_groups(2, 130, 64);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].local_positions, (0..64).collect::<Vec<_>>());
        assert_eq!(groups[2].local_positions, (128..130).collect::<Vec<_>>());
        let flattened = groups
            .iter()
            .flat_map(|group| group.local_positions.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(flattened, (0..130).collect::<Vec<_>>());
    }

    #[test]
    fn group_mapping_is_deterministic() {
        assert_eq!(
            group_for_local_index(3, 127, 64),
            GroupId {
                local_code_index: 3,
                local_group_index: 1
            }
        );
        assert_eq!(
            group_for_local_index(3, 128, 64),
            GroupId {
                local_code_index: 3,
                local_group_index: 2
            }
        );
    }
}
