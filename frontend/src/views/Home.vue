<template>
  <div>
    <h1>{{ user?.username }}'s Articles</h1>

    <form @submit.prevent="onSearch" class="search-form">
      <div class="row">
        <input id="searchInput" v-model="searchTerm" type="text" placeholder="Tapez votre recherche..." />
      </div>
    </form>
    <p v-if="searchQueryRaw" class="search-results" v-html="`Résultats pour : ${searchQueryRaw}`"></p>

    <ul class="article-list">
      <li v-for="a in filteredArticles" :key="a.id">
        <router-link :to="{ name: 'Article', params: { id: a.id } }">
          {{ a.title }}
        </router-link>
        <button @click="deleteArticle(a.id)">❌</button>
      </li>
    </ul>

    <form @submit.prevent="exportData" class="export-form">
      <div class="form-group">
        <label for="exportUrl">URL to export articles:</label>
        <div class="row">
          <input id="exportUrl" v-model="exportUrl" type="text" placeholder="https://exemple.com/endpoint" required />
          <button type="submit">Exporter</button>
        </div>
      </div>
      <p v-if="statusMessage" :class="{ error: isError }">{{ statusMessage }}</p>
    </form>
  </div>
</template>

<script setup>
import { user } from '../store/user'
import api from '../services/api';
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import DOMPurify from "dompurify";

const articles = ref([])
const searchTerm = ref('')
const exportUrl = ref('')
const statusMessage = ref('')
const isError = ref(false)

const route = useRoute()
const router = useRouter()

const searchQueryRaw = computed(() => {
  const s = route.query.search
  return typeof s === 'string' ? DOMPurify.sanitize(s) : ''
})

const filteredArticles = computed(() => {
  if (!searchQueryRaw.value) return articles.value
  return articles.value.filter(a =>
    a.title.toLowerCase().includes(searchQueryRaw.value.toLowerCase())
  )
})

async function exportData() {
  statusMessage.value = ''
  isError.value = false

  try {
    new URL(exportUrl.value)
  } catch {
    isError.value = true
    statusMessage.value = 'Invalid URL.'
    return
  }

  try {
    await api.get('/articles/export', {
      params: { to: exportUrl.value }
    })
    statusMessage.value = 'Data exported !'
  } catch (e) {
    isError.value = true
    if (e.response?.data?.error) {
      statusMessage.value = `Erreur : ${e.response.data.error}`
    } else {
      statusMessage.value = 'Export failed.'
    }
  }
}

async function updateArticles() {
  const { data } = await api.get('/articles')
  articles.value = data
}

async function deleteArticle(id) {
  await api.delete(`/articles/${id}`)
  await updateArticles()
}

watch(
  () => route.query.search,
  newVal => {
    if (typeof newVal === 'string') {
      searchTerm.value = newVal
    }
  }
)

function onSearch() {
  router.replace({
    name: route.name || 'Home',
    query: { ...route.query, search: searchTerm.value }
  })
}

onMounted(async () => {
  searchTerm.value = searchQueryRaw.value
  await updateArticles()
})
updateArticles()
</script>

<style scoped>
li {
  display: flex;
  justify-content: space-between;
}

.export-form {
  margin-bottom: 2rem;
  padding: 1rem;
  border: 1px solid #ddd;
  background: #fdfdfd;
}

.export-form .form-group {
  margin-bottom: 1rem;
}

.export-form input {
  width: 100%;
  padding: 0.5rem;
  box-sizing: border-box;
}

.export-form button {
  padding: 0.5rem 1rem;
  background-color: #42b983;
  border: none;
  color: white;
  cursor: pointer;
}

.export-form button:hover {
  background-color: #369870;
}

.error {
  color: red;
  margin-top: 0.5rem;
}

.row {
  display: flex;
  justify-content: center;
  gap: 1rem;
}

.search-form input {
  max-width: 300px;
  border-radius: 8px;
  border-width: 1px;
}
</style>
