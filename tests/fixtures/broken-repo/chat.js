// Deliberately insecure sample: model output reaching the DOM. Planted for tests
// (task 23.5.3 — the innerHTML rule had no fixture, so it had never fired anywhere).
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenerativeAI } from "@google/generative-ai";
import ollama from "ollama";

const openai = new OpenAI();
const anthropic = new Anthropic();
const gemini = new GoogleGenerativeAI(process.env.KEY).getGenerativeModel({ model: "gemini-2.5-pro" });
const out = document.getElementById("out");

export async function renderChat(prompt) {
  const completion = await openai.chat.completions.create({ model: "gpt-5", messages: [{ role: "user", content: prompt }] });
  out.innerHTML = completion.choices[0].message.content;
}

export async function renderResponses(prompt) {
  const response = await openai.responses.create({ model: "gpt-5", input: prompt });
  out.innerHTML = response.output_text;
}

export async function renderClaude(prompt) {
  const message = await anthropic.messages.create({ model: "claude-opus-5", messages: [{ role: "user", content: prompt }] });
  out.innerHTML = message.content[0].text;
}

export async function renderGemini(prompt) {
  const result = await gemini.generateContent(prompt);
  out.innerHTML = result.response.text();
}

export async function renderChain(chain, prompt) {
  const answer = await chain.invoke({ question: prompt });
  out.innerHTML = answer.content;
}

export async function renderOllama(prompt) {
  const reply = await ollama.chat({ model: "llama3", messages: [{ role: "user", content: prompt }] });
  out.innerHTML = reply.message.content;
}

export function renderSafely(text) {
  out.textContent = text;
}
