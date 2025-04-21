import random
import time
from main import create_voting_system, vote

def test_voting_system():
    # 创建投票系统
    candidates, audit_node, voting_nodes, tally_node = create_voting_system()

    # 生成随机100个ID
    voter_ids = random.sample(range(1, 1000), 100)

    # 生成预期结果
    expected_results = {candidate: 0 for candidate in candidates}
    voter_choices = {}
    for voter_id in voter_ids:
        candidate_id = random.choice(list(tally_node.candidate_to_id.values()))
        voter_choices[voter_id] = candidate_id
        expected_results[tally_node.id_to_candidate[candidate_id]] += 1

    # 记录投票时间
    total_voting_time = 0

    # 进行投票
    for voter_id, candidate_id in voter_choices.items():
        start_time = time.time()  # 记录投票开始时间
        vote(voter_id, candidate_id, voting_nodes, audit_node, tally_node)
        end_time = time.time()  # 记录投票结束时间
        total_voting_time += (end_time - start_time)  # 累加投票时间

    # 计算平均投票时间
    average_voting_time = total_voting_time / len(voter_ids)
    print(f"平均投票时间：{average_voting_time:.4f} 秒")

    # 计票
    all_votes = []
    for node in voting_nodes:
        all_votes.extend(node.encrypted_votes)
    if tally_node.request_shares_and_decrypt(voting_nodes, audit_node.threshold):
        tally_node.tally_votes(all_votes, voting_nodes[0].palliar_public_key)
        final_results = tally_node.decrypt_tally(tally_node.private_key)
        print("最终结果：")
        for candidate, votes in final_results.items():
            print(f"{candidate}: {votes} 票")
    else:
        print("未能获取足够份额以解密计票结果。")

    # 打印预期结果
    print("\n预期结果：")
    for candidate, votes in expected_results.items():
        print(f"{candidate}: {votes} 票")

    # 计算准确度
    accuracy = sum(min(final_results[candidate], expected_results[candidate]) for candidate in candidates) / sum(expected_results.values())
    print(f"\n准确度：{accuracy:.2%}")

if __name__ == "__main__":
    test_voting_system()