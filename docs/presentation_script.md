# Presentation Script: Dataset and Model Development

**[Greeting and Introduction]**
"Good morning, respected panel members. Today, I will be walking you through the core engine of our project: the dataset preparation and the machine learning model development. This is where the foundation of our multi-layer phishing detection system lies."

---

## 1. Dataset Development (V2)

"To train an effective model, we needed data that reflects modern threats. Traditional datasets only contain human-written phishing, which fails to capture the grammatical perfection of modern AI-generated attacks. 

To solve this, we compiled a custom dataset of exactly **9,600 samples**, drawing from 7 different corpora. 

**The Raw Data Sources (The 7 Corpora):**
We aggregated data from well-known public security corpora and generated our own novel data:
1.  **Enron Email Corpus (2,993 samples):** A famous archive of internal corporate emails, providing high-quality examples of normal, legitimate communication.
2.  **SpamAssassin Corpus (1,000 samples):** A classic open-source spam filtering dataset used for mixed legitimate/ham emails.
3.  **Phishing Email Dataset (1,500 samples):** A standard public dataset of known, older phishing lures.
4.  **Nazario Phishing Corpus (991 samples):** A widely respected, real-world archive of early phishing attacks.
5.  **Nigerian Fraud Corpus (995 samples):** A specialized dataset containing traditional '419' advance-fee fraud emails.
6.  **Human-Generated (131 samples):** A small set of manually curated mixed test cases.
7.  **Custom LLM-Generated (1,990 samples):** This is the major novelty of our work. We specifically prompted modern Large Language Models to generate highly deceptive, zero-day phishing attacks, as well as perfectly polite legitimate emails (split evenly). This ensures the model learns to catch AI-written threats.

**How did we process the raw data?** 
Raw emails are incredibly messy. We wrote a custom Python preprocessing pipeline that cleans the data before the model ever sees it:
1. First, we strip out all raw HTML tags to get pure text.
2. We then anonymize the data by replacing all actual URLs with a generic `[URL]` token and email addresses with an `[EMAIL]` token. This is critical: it prevents the model from simply memorizing known malicious URLs and forces it to actually learn the *linguistic context* and manipulative language around those links.
3. Finally, we remove special characters, normalize whitespace, and convert everything to lowercase.

**Why exactly 9,600 samples? Why not more or less?**
This specific number allowed us to create a perfectly balanced dataset (about 52% legitimate emails and 48% phishing emails). 
*   **Why not more?** Because we are fine-tuning a pre-trained language model rather than training a model from scratch, we do not need millions of rows. Adding too much redundant data would just increase training time without significant accuracy gains. 
*   **Why not less?** Using fewer samples risks the model not seeing enough variety. 9,600 high-quality, diverse samples from 7 different sources hits the 'sweet spot'—providing enough diversity to generalize well across different types of phishing, while remaining computationally efficient enough to train on a single GPU."

---

## 2. Base Model Selection and Transfer Learning

"**Why not build our own model from scratch?**
Training a Transformer model entirely from scratch requires massive amounts of text—like the entirety of Wikipedia and the BookCorpus—and hundreds of GPUs running for weeks to learn basic English grammar. It is highly inefficient. 

Instead, we utilized **Transfer Learning**. We loaded the pre-trained `distilbert-base-uncased` base model using the HuggingFace Transformers library. This base model already possessed a deep, foundational understanding of the English language. All we had to do was attach a custom 4-class classification head to it and fine-tune those weights on our 9,600 phishing samples. We essentially took a model that knows English, and taught it to detect phishing.

**Why DistilBERT? (Addressing the Shift from Random Forest)**
Initially, we experimented with a Random Forest classifier layered with a 3-layer NLP approach using TF-IDF. However, following the panel's valuable feedback, we pivoted to a transformer. 

Here is exactly why that change was necessary:
Random Forest relies on manual feature engineering and keyword frequencies. LLM-generated phishing emails are dangerous precisely because they *lack* traditional spam keywords and grammar mistakes. Transformers like DistilBERT understand the **bidirectional contextual semantic meaning** of a sentence, allowing them to detect the subtle structural patterns of AI authorship.

Since our model operates as Layer 1 in a real-time, 6-layer pipeline, latency is critical. We specifically chose DistilBERT because it uses knowledge distillation to be **40% smaller and 60% faster** than standard BERT, while retaining **97% of BERT's performance**.

**Why only 3 Epochs for Training?**
During our fine-tuning process, we trained the model for exactly 3 epochs. The panel might wonder why we didn't train for 10 or 20 epochs. The reason is **overfitting**. 
Because we are using Transfer Learning, the base DistilBERT model already has a sophisticated understanding of language. It only takes a few passes over our 9,600 samples to learn the specific nuances of phishing. Training for more than 3 epochs on a dataset of this size would cause the model to memorize the training data rather than generalizing to unseen threats. At 3 epochs, the model converged perfectly, achieving an optimal balance with 99.17% validation accuracy."

---

## 3. Internal Architecture of DistilBERT

"To understand how the model operates internally, let's break down its architecture into simple terms:
*   **66 Million Parameters:** Think of parameters as the mathematical 'brain cells' of the model. These are the 66 million individual numerical weights that the model adjusted during training to learn the exact patterns of phishing. Standard BERT has 110 million; our model uses 66 million to be much faster and lighter.
*   **512 Tokens at a time:** A token is roughly equivalent to a word or a sub-word. A limit of 512 tokens means our model can 'read' and process about 400 to 500 words of an email in a single pass to understand the full context. If an email is longer than this, it gets **truncated**—meaning the model reads the first 512 tokens and completely ignores the rest. This is a standard hardware limitation, but since most phishing indicators (like urgency or deceptive links) appear early in the email body, ignoring the tail end does not negatively impact our accuracy.
*   **6 Transformer Layers:** These are the sequential processing stages. The flow of data through these 6 layers is **serial**. As the text passes from Layer 1 to Layer 6, the model extracts deeper and deeper meaning. Layer 1 might recognize basic grammar, while Layer 6 recognizes complex manipulative intent.
*   **Multi-Head Attention (12 Heads):** Within each of the 6 layers, there are 12 'heads'. This means the model looks at the sentence from 12 different perspectives simultaneously in **parallel**. For example, one head might focus on the relationship between the subject 'Account' and the verb 'Suspended', while another head simultaneously analyzes the urgency of the tone."

---

## 4. Input Processing and Internal Execution

"Finally, how does the data flow from a raw email to a final prediction during live inference? It happens in three main stages:

**1. Preprocessing at Runtime:**
Just like our training pipeline, we combine the live email subject and body and pass it into our `clean_text` utility, applying the exact same anonymization with `[URL]` and `[EMAIL]` placeholders. 

**2. Tokenization:**
The cleaned text is passed to the WordPiece tokenizer, which chops words into sub-words (tokens), maps them to their vocabulary IDs, and generates an attention mask. If the text is over 512 tokens, it is safely truncated.

**3. Internal Inference:**
These tensors are moved to the GPU and passed into our fine-tuned DistilBERT model. As the data passes serially through the 6 transformer layers, the parallel attention heads calculate how much focus each token should place on every other token. 
By the end of the 6th layer, the model aggregates all this contextual understanding into a special `[CLS]` (Classification) token at the start of the sequence.

This `[CLS]` token's vector is then passed through our custom Linear Classification Head, which outputs raw logits for our 4 classes. We apply a Softmax function to convert these into probabilities, allowing us to map the output to either 'Phishing' or 'Legitimate' and extract a precise confidence score.
**Conclusion:**
By combining this robust 9,600-sample dataset with the contextual power of Transfer Learning, we achieved exceptional detection rates.

---

## 5. Model Evaluation Metrics

"So, how well did this fine-tuned DistilBERT model perform? 
We evaluated it on a strictly separated test set of 961 unseen emails. The results were outstanding:

*   **Overall Accuracy:** 99.17%
*   **Precision:** 98.92% (When we flagged an email as phishing, we were right nearly 99% of the time, minimizing annoying false positives for users).
*   **Recall:** 99.35% (Out of all actual phishing emails, we successfully caught over 99% of them).
*   **F1 Score:** 99.14% (A near-perfect balance between precision and recall).

To put this into perspective, let's look at the Confusion Matrix for those 961 test emails:
*   We correctly identified **494 Legitimate** emails and **459 Phishing** emails.
*   We had only **5 False Positives** (legitimate emails incorrectly marked as phishing).
*   We had only **3 False Negatives** (phishing emails that slipped through).

Most importantly, when evaluating specifically against the **LLM-generated phishing emails**, the model achieved a **99.49% accuracy**, missing only 1 single AI-generated threat out of 197 samples in the test set."

---

## 6. Model Risk Aggregation (Layer 1)

"How do we turn the model's mathematical output into an actionable verdict? 
The model outputs a raw probability score via a Softmax function—for example, it might predict a '0.92 probability of Phishing'. 

We map this raw confidence score to three clear Risk Levels:
*   **HIGH Risk:** Confidence score of 0.85 or higher.
*   **MEDIUM Risk:** Confidence score between 0.50 and 0.84.
*   **LOW (Safe) Risk:** Confidence score below 0.50.

But this model does not make the final decision alone. It acts as **Layer 1** in our overall 6-layer Risk Aggregator. 
The DistilBERT score contributes exactly **20% base weight** to the final overall risk score of the entire system. 

Furthermore, we built an AI Authorship modifier. If our separate statistical detector flags the text as AI-generated, AND the DistilBERT model flags it as phishing, the aggregator applies a specific **+0.08 risk boost** to the final combined score, ensuring that highly deceptive, LLM-generated phishing attempts are heavily penalized."

---

## 7. End-to-End API Flow (Frontend to Model)

"Finally, I want to briefly explain how this model is actually used in practice. How does the text get from the user to the model, and how does the verdict get back?

1.  **The Request:** When a user opens an email in Gmail, our **Chrome Extension** (or our web dashboard) extracts the raw email body and headers. The frontend packages this into a JSON payload and sends it via an HTTP POST request to our FastAPI backend endpoint (`/api/v1/deep-analyze`).
2.  **Routing to the Model:** The FastAPI backend receives the request. The text is immediately passed to our `EmailClassifier` service, which holds the DistilBERT model in active memory. 
3.  **Model Processing:** The text undergoes the preprocessing, tokenization, and inference we discussed earlier. The model spits out a raw result tuple: `(is_phishing, confidence, label, risk_level)`.
4.  **The Aggregator:** The backend doesn't just stop there. It takes this model output (Layer 1) and combines it with the results from the URL analyzer, Web Crawler, Visual Analyzer, and Header Forensics. 
5.  **The Response:** The backend packages the final combined Risk Verdict, along with the detailed breakdown of the model's token highlights (Explainable AI), into a large 18-field JSON response. This is sent back to the frontend, which instantly updates the user interface with a red, amber, or green warning banner and a visual risk gauge."
