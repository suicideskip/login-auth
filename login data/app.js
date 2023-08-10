require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API! '})
})

app.get("/user/:id", checkToken, async(req, res) => {

    const id = req.params.id

    const user = await User.findById(id, '-password')

    if(!user){
        res.status(404).json({ msg: "Usuário não encontrado"})
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({ msg: 'Acesso negado'})
    }

    try {
        
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch (error) {
        console.log(error)

        return res.status(400).json({ msg: 'Token invalido'})
    }
}

// register user
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    //validations
    if(!name){
        return res.status(422).json({ msg: 'O nome é obrigatório'})
    }

    if(!password){
        return res.status(422).json({ msg: 'A senha é obrigatória'})
    }

    if(!email){
        return res.status(422).json({ msg: 'O email é obrigatório'})
    }

    if(password !== confirmpassword){
        return res.status(422).json({ msg: 'As senhas não conferem'})
    }

    const userExists = await User.findOne({ email: email })

    if(userExists) {
        return res.status(422).json({ msg: 'Usuário ja cadastrado!'})
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuário cadastrado!'})
    } catch (error) {
        console.log(error)

        return res.status(500).json({ msg: error})
    }
})

//Login User
app.post("/auth/login", async(req, res) => {

    const {email, password} = req.body

    if(!password){
        return res.status(422).json({ msg: 'A senha é obrigatória'})
    }

    if(!email){
        return res.status(422).json({ msg: 'O email é obrigatório'})
    }

    const user = await User.findOne({ email: email })

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!'})
    }

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(404).json({ msg: 'senha inválida'})
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id
        }, secret,
        )

        res.status(200).json({ msg: "auth relizada com sucesso", token})
    } catch (err) {
        console.log(error)
        res.status(500).json({ msg: "ocorreu um erro no servidor" })
    }

})

// credentials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS
const Url = `mongodb+srv://${dbUser}:${dbPass}@cluster0.sgctxc1.mongodb.net/?retryWrites=true&w=majority`


mongoose.connect(Url).then(() => {
    app.listen(3000)
    console.log("conectou com sucesso ao banco!")
}).catch((err) => console.log(err))

