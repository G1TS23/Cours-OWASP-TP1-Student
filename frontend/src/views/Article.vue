<template>
  <div v-if="article">
    <h1>{{ article.title }}</h1>
    <p v-html="safeContent"></p>
    <router-link :to="{ name: 'EditArticle', params: { id }}">Edit</router-link>
  </div>
  <p v-else>Loading…</p>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../services/api'
import DOMPurify from 'dompurify'

const props = defineProps({
  id: {
    type: String,
    required: true
  }
})

const article = ref(null)
let safeContent = ref('')

onMounted(async () => {
  try {
    const res = await api.get(`/articles/${props.id}`)
    article.value = res.data
    console.log(article.value)
    safeContent = DOMPurify.sanitize(article.value.content)

  } catch {
    article.value = null
  }
})
</script>
