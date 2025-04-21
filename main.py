import base64
import json
import random
import tkinter as tk
from tkinter import messagebox

import phe as paillier
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from sslib import shamir  # 导入Shamir分享器

# 全局字典存储Voter实例
voters = {}

# 导出私钥为JSON兼容格式
def export_private_key(private_key):
    private_key_info = {
        'p': str(private_key.p),
        'q': str(private_key.q),
        'public_key': {
            'n': str(private_key.public_key.n),
        }
    }
    return json.dumps(private_key_info)

# 从JSON兼容格式导入私钥
def import_private_key(json_str):
    private_key_info = json.loads(json_str)
    public_key = paillier.PaillierPublicKey(int(private_key_info['public_key']['n']))
    private_key = paillier.PaillierPrivateKey(public_key,
                                              int(private_key_info['p']),
                                              int(private_key_info['q']))
    return private_key

# 模拟生成RSA密钥对
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 使用私钥为消息生成签名，并返回Base64编码后的字符串
def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

# 使用公钥验证签名，传入Base64编码后的签名字符串
def verify_signature(public_key, message, signature_base64):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    signature = base64.b64decode(signature_base64)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

class Voter:
    def __init__(self, voter_id):
        self.voter_id = voter_id
        self.private_key, self.public_key = generate_rsa_keypair()
        self.has_voted = False

    def vote(self, candidate_id, voting_node, audit_node, tally_node):
        if not self.has_voted:
            encrypted_vote = voting_node.palliar_public_key.encrypt(1)

            # 将 EncryptedNumber 对象转换为可序列化的字典
            encrypted_vote_dict = {
                'ciphertext': str(encrypted_vote.ciphertext()),
                'exponent': encrypted_vote.exponent,
            }

            vote = {
                'voter_id': self.voter_id,
                'candidate_id': candidate_id,
                'encrypted_vote': encrypted_vote_dict,
                'public_key': self.public_key.decode()
            }

            vote_message = json.dumps(vote, sort_keys=True, separators=(',', ':')).encode('utf-8')
            vote['signature'] = sign_message(self.private_key, vote_message)

            if audit_node.verify_vote(vote, vote_message):
                success = voting_node.receive_vote(vote, tally_node)
                if success:
                    self.has_voted = True
                    return f"选民 {self.voter_id} 投给了候选人ID: {candidate_id}"
                else:
                    return "投票失败。"
            else:
                return "签名验证失败。"
        else:
            return "您已经投过票了。"

class VotingNode:
    def __init__(self):
        self.encrypted_votes = []
        self.palliar_public_key = None
        self.shamir_share = None  # 存储从审计节点收到的Shamir份额

    def set_public_key(self, palliar_public_key):
        self.palliar_public_key = palliar_public_key

    def receive_vote(self, vote, tally_node):
        if tally_node.has_tallied:
            return False  # 如果已经计票，不再接受新的投票
        if not any(v['voter_id'] == vote['voter_id'] for v in self.encrypted_votes) and self.palliar_public_key is not None:
            self.encrypted_votes.append(vote)
            return True  # 成功接收投票
        return False  # 投票失败

    def get_shamir_share(self):
        return self.shamir_share

class AuditNode:
    def __init__(self, threshold=3, total_nodes=5):
        self.threshold = threshold
        self.total_nodes = total_nodes

    def generate_and_distribute_keys(self, voting_nodes, tally_node):
        public_key, private_key = paillier.generate_paillier_keypair()

        # 将私钥转换为JSON兼容字符串形式，以便用于Shamir分享
        private_key_json = export_private_key(private_key)

        # 使用sslib的shamir模块来创建Shamir份额
        split_result = shamir.to_base64(shamir.split_secret(
            bytes(private_key_json, 'utf-8'), self.threshold, self.total_nodes
        ))
        required_shares = split_result['required_shares']
        prime_mod = split_result['prime_mod']
        shares = split_result['shares']

        # 分发公共密钥和私钥份额
        for i, node in enumerate(voting_nodes):
            node.set_public_key(public_key)
            if i < len(shares):
                # 提取索引值和份额值
                node.shamir_share = shares[i]
            else:
                raise ValueError("生成的份额数量不足，无法分发。")

        # 分发required_shares 和 prime_mod
        tally_node.set_shamir(required_shares, prime_mod)

    def verify_vote(self, vote, original_vote_message):
        return verify_signature(vote['public_key'].encode(), original_vote_message, vote['signature'])

class TallyNode:
    def __init__(self, candidates):
        self.candidates = candidates
        self.candidate_to_id, self.id_to_candidate = self._generate_random_mapping(candidates)
        self.tally = {candidate_id: None for candidate_id in self.candidate_to_id.values()}
        self.private_key = None  # 用于解密的私钥
        self.required_shares = None
        self.prime_mod = None
        self.has_tallied = False  # 添加计票状态标志

    def set_shamir(self, required_shares, prime_mod):
        self.required_shares = required_shares
        self.prime_mod = prime_mod

    def _generate_random_mapping(self, candidates):
        ids = list(range(len(candidates)))
        random.shuffle(ids)
        candidate_to_id = {name: id for name, id in zip(candidates, ids)}
        id_to_candidate = {id: name for name, id in candidate_to_id.items()}
        return candidate_to_id, id_to_candidate

    def tally_votes(self, votes, palliar_public_key):
        if self.has_tallied:
            return  # 如果已经计票，直接返回

        for vote in votes:
            candidate_id = vote['candidate_id']

            if self.tally[candidate_id] is None:
                self.tally[candidate_id] = palliar_public_key.encrypt(0)

            encrypted_vote = paillier.EncryptedNumber(
                palliar_public_key,
                int(vote['encrypted_vote']['ciphertext']),
                int(vote['encrypted_vote']['exponent'])
            )

            self.tally[candidate_id] += encrypted_vote

        for candidate_id in self.tally:
            if self.tally[candidate_id] is None:
                self.tally[candidate_id] = palliar_public_key.encrypt(0)

        self.has_tallied = True  # 设置计票状态为True

    def decrypt_tally(self, private_key):
        results = {}
        for candidate_id, encrypted_sum in self.tally.items():
            if encrypted_sum is not None:
                decrypted_sum = private_key.decrypt(encrypted_sum)
                candidate_name = self.id_to_candidate[candidate_id]
                results[candidate_name] = decrypted_sum
            else:
                results[self.id_to_candidate[candidate_id]] = 0
        return results

    def request_shares_and_decrypt(self, voting_nodes, threshold):
        shares = [node.get_shamir_share() for node in voting_nodes if node.get_shamir_share() is not None][:threshold]
        recover_result = {
            'required_shares': self.required_shares,
            'prime_mod': self.prime_mod,
            'shares': shares
        }
        if len(shares) >= threshold:
            private_key_json = shamir.recover_secret(shamir.from_base64(recover_result)).decode('utf-8')
            self.private_key = import_private_key(private_key_json)
            return True
        return False

def vote(voter_id, candidate_id, voting_nodes, audit_node, tally_node):
    if tally_node.has_tallied:
        return "投票已结束。"  # 如果已经计票，返回投票已结束的提示
    if voter_id not in voters:
        voters[voter_id] = Voter(voter_id)
    voter = voters[voter_id]
    chosen_voting_node = random.choice(voting_nodes)
    result = voter.vote(candidate_id, chosen_voting_node, audit_node, tally_node)
    return result

def create_voting_system():
    candidates = ['弃权', 'Alice', 'Bob', 'Charlie']
    audit_node = AuditNode(threshold=3, total_nodes=5)
    voting_nodes = [VotingNode() for _ in range(audit_node.total_nodes)]
    tally_node = TallyNode(candidates)

    # 审计节点生成并分发Paillier密钥对
    audit_node.generate_and_distribute_keys(voting_nodes, tally_node)

    return candidates, audit_node, voting_nodes, tally_node

def create_gui(candidates, audit_node, voting_nodes, tally_node):
    root = tk.Tk()
    root.title("电子投票系统")

    root.geometry("400x300")
    root.resizable(True, True)

    for i in range(4):
        root.grid_rowconfigure(i, weight=1)
    for i in range(2):
        root.grid_columnconfigure(i, weight=1)

    tk.Label(root, text="选民ID:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
    voter_id_entry = tk.Entry(root)
    voter_id_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    tk.Label(root, text="候选人:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
    candidate_var = tk.StringVar(root)
    candidate_var.set(candidates[0])  # 默认选择第一个候选人
    candidate_menu = tk.OptionMenu(root, candidate_var, *candidates)
    candidate_menu.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    def vote_button_click():
        voter_id = int(voter_id_entry.get())
        candidate_id = tally_node.candidate_to_id[candidate_var.get()]
        result = vote(voter_id, candidate_id, voting_nodes, audit_node, tally_node)
        messagebox.showinfo("投票结果", result)

    vote_button = tk.Button(root, text="投票", command=vote_button_click)
    vote_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def tally_button_click():
        if not tally_node.has_tallied:
            all_votes = []
            for node in voting_nodes:
                all_votes.extend(node.encrypted_votes)
            if tally_node.request_shares_and_decrypt(voting_nodes, audit_node.threshold):
                tally_node.tally_votes(all_votes, voting_nodes[0].palliar_public_key)
                final_results = tally_node.decrypt_tally(tally_node.private_key)
                result_str = "最终结果：\n"
                for candidate, votes in final_results.items():
                    result_str += f"{candidate}: {votes} 票\n"
                messagebox.showinfo("计票结果", result_str)
            else:
                messagebox.showerror("计票失败", "未能获取足够份额以解密计票结果。")
        else:
            messagebox.showinfo("计票结果", "计票已完成。")

    tally_button = tk.Button(root, text="计票", command=tally_button_click)
    tally_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    root.mainloop()

if __name__ == "__main__":
    candidates, audit_node, voting_nodes, tally_node = create_voting_system()
    create_gui(candidates, audit_node, voting_nodes, tally_node)