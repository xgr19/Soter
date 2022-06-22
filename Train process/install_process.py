# -*- coding: utf-8 -*-
# @Author: cuicp
# @Date:   2022-06-20 15:58:51
# @Last Modified by:   cuicp
# @Last Modified time: 2022-06-21 14:22:48

from collections import deque
import numpy as np
import joblib

from sklearn.tree._tree import TREE_UNDEFINED


NUM_STAGES = 8
ALPHA = 0.7
RULES_PER_STAGE = {16: 4050, 8: 1067, 1: 810, 0: 410}  # 0, 1, 8, 16

FEATURE_NAMES = ['Flags', 'HeaderLength', 'IPProtocol', 'TCPflags', 'TOS', 'TTL']
FEATURE_BITS = [2, 4, 8, 6, 8, 8]
PORTS = [1, 2]
command_file = ''
ternary_idx = 1


def range2ternary(range_begin, range_end, mask_width):
    list_mask_value = []

    def tcam_range(range_begin, range_end, mask_width, list_mask_value):
        for i in range(64):
            mask = 0x1 << i
            if ((range_begin & mask) or (mask > range_end)):
                break

        for j in range(i, -1, -1):
            stride = (1 << j) - 1
            if (range_begin + stride == range_end):
                tuple_mask_value = (~(range_begin ^ range_end) & ((1 << mask_width) - 1), range_begin)
                list_mask_value.append(tuple_mask_value)
                return
            elif (range_begin + stride < range_end):
                tcam_range(range_begin, range_begin + stride, mask_width, list_mask_value)
                tcam_range(range_begin + stride + 1, range_end, mask_width, list_mask_value)
                return
            else:
                continue

    if (range_begin <= range_end):
        tcam_range(range_begin, range_end, mask_width, list_mask_value)
    else:
        input('=== Error range2ternary')

    return list_mask_value


# stage = 9
def export_p4_rules(tree, stages, ternary_idx, command_file):
    # [curr_node, prev_node, thresh_flag]
    queues = [deque([(0, 0, 0)]), deque()]

    tree_max_depth = tree.tree_.max_depth
    tree_n_outputs = tree.tree_.n_outputs
    tree_n_classes = 2
    tree_classes = tree.classes_
    tree_feature = tree.tree_.feature
    tree_threshold = tree.tree_.threshold
    tree_value = tree.tree_.value
    tree_children_left = tree.tree_.children_left
    tree_children_right = tree.tree_.children_right

    # ternary
    def gen_ternary(idx, level_stages, prev_node, thresh_flag, curr_node,
                    left, right, less_than_feature, bit_width, leftbranch):
        if FEATURE_BITS[idx] > ternary_idx:
            # right = right+1 if leftbranch else right
            ternaries = [(right, left)]
        else:
            # input & mask = value
            # 0 & 1 = 0 => left
            # 1 & 1 = 1 => right
            ternaries = range2ternary(left, right, bit_width)
        for mask_value in ternaries:
            str_ = ('bfrt.simple_l3_test.pipe.Ingress.' + \
                    'level%d.node.add_with_CheckFeature(%d, %d, ') % (
                       level_stages, prev_node, thresh_flag)

            paras = []
            for i in range(len(FEATURE_NAMES)):
                if i != idx and FEATURE_BITS[i] > ternary_idx:
                    paras.append(0)
                    paras.append((1 << FEATURE_BITS[i]) - 1)
                elif i != idx and FEATURE_BITS[i] <= ternary_idx:
                    paras.extend([0, 0])
                else:
                    paras.append(mask_value[1])  # value
                    paras.append(mask_value[0])  # mask
            str_ += ','.join(map(str, paras))

            # MATCH_PRIORITY, node_id, less_than_feature
            str_ += ', 0, %d, %d)\n' % (curr_node, less_than_feature)
            command_file.write(str_)

    for level in range(0, tree_max_depth + 1):
        tmpque = queues[level % len(queues)]
        while tmpque:
            curr_node, prev_node, thresh_flag = tmpque.popleft()
            if tree_feature[curr_node] == TREE_UNDEFINED:  # leaf
                if tree_n_outputs == 1:
                    value = tree_value[curr_node][0]
                else:
                    value = tree_value[curr_node].T[0]
                class_id = np.argmax(value)
                if (tree_n_classes != 1 and tree_n_outputs == 1):
                    class_id = int(tree_classes[class_id])

                # prev_node_id, threshold_flag
                str_ = ('bfrt.simple_l3_test.pipe.Ingress.' + \
                        'level%d.node.add_with_SetClass(%d, %d') % (
                           level % stages, prev_node, thresh_flag)
                for i in FEATURE_BITS:
                    if i > ternary_idx:
                        str_ += ', %d, %d' % (0, (1 << i) - 1)
                    else:
                        str_ += ', 0, 0'
                # MATCH_PRIORITY, node_id, class_id
                str_ += ', 0, %d, %d)\n' % (curr_node, PORTS[class_id])
                command_file.write(str_)
            else:  # children
                feature_id = tree_feature[curr_node]
                threshold = int(float(tree_threshold[curr_node]))
                gen_ternary(feature_id, level % stages, prev_node, thresh_flag, curr_node,
                            # less_than_feature=1
                            0, threshold, 1, FEATURE_BITS[feature_id], leftbranch=True)
                gen_ternary(feature_id, level % stages, prev_node, thresh_flag, curr_node,
                            threshold + 1, (1 << FEATURE_BITS[feature_id]) - 1,
                            # less_than_feature=0
                            0, FEATURE_BITS[feature_id], leftbranch=False)

                # children
                queues[(level + 1) % len(queues)].append((
                    int(tree_children_left[curr_node]), curr_node, 1))
                queues[(level + 1) % len(queues)].append((
                    int(tree_children_right[curr_node]), curr_node, 0))


if __name__ == '__main__':
    tree = joblib.load("Tree_0.pkl")
    with open('command_p4.txt', 'w') as f:
        export_p4_rules(tree, stages=9, ternary_idx=1, command_file=f)

