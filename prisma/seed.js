const bcrypt = require('bcryptjs')
const {PrismaClient} = require('@prisma/client')
const prisma = new PrismaClient()

const password = bcrypt.hashSync('123456')
const userData = [
    {firstName: 'aom', lastName:'fa', username: 'aommy',  password, email: 'aommy@gmail.com', phone:'0969495505'  },
    {firstName: 'lo', lastName:'de', username: 'youLo',  password, email: 'Lo123@gmail.com', phone:'0957745795'  },
    {firstName: 'nor', lastName:'as', username: 'norman', password, email: 'norman@gmail.com', phone:'0934788541' },
]

const run = async () => {
    await prisma.user.createMany({
        data : userData
    })

}

run()