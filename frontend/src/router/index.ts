import { createRouter, createWebHistory } from 'vue-router'
import { user } from '../store/user'

import Home          from '../views/Home.vue'
import Login         from '../views/Login.vue'
import Register      from '../views/Register.vue'
import Article       from '../views/Article.vue'
import CreateArticle from '../views/CreateArticle.vue'
import EditArticle   from '../views/EditArticle.vue'
import Admin         from '../views/Admin.vue'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home,
    meta: { requiresAuth: true }
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { onlyGuest: true }
  },
  {
    path: '/register',
    name: 'Register',
    component: Register,
    meta: { onlyGuest: true }
  },
  {
    path: '/articles/create',
    name: 'CreateArticle',
    component: CreateArticle,
    meta: { requiresAuth: true }
  },
  {
    path: '/articles/:id',
    name: 'Article',
    component: Article,
    props: true,
    meta: { requiresAuth: true }
  },
  {
    path: '/articles/:id/edit',
    name: 'EditArticle',
    component: EditArticle,
    props: true,
    meta: { requiresAuth: true }
  },
  {
    path: '/admin',
    name: 'Admin',
    component: Admin,
    meta: {
      requiresAuth: true,
      onlyAdmin: true
    }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// --- Global Guard ---
router.beforeEach((to, _from, next) => {
  const isLogged = !!user.value
  if (to.meta.requiresAuth && !isLogged) return next({ name: 'Login' })
  if (to.meta.onlyGuest && isLogged) return next({ name: 'Home' })
  if (to.meta.onlyAdmin && user.value?.role !== 'admin') return next({ name: 'Home' })
  next()
})

export default router
