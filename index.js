import express from 'express';
import Datastore from 'nedb-promises';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
import {config} from './config.js'

const users = Datastore.create('User.db');

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
	res.send('Добро пожалвоать!');
});

app.post('/api/auth/register', async (req, res) => {
	try {
		const { name, email, password } = req.body;

		if (!name || !email || !password) {
			return res.status(422).json({ message: 'Укажите, пожалуйста все поля!' });
		}

		if (await users.findOne({ email })) {
			return res.status(409).json({ message: 'Такой email уже существует!' });
		}

		const hashedPassword = await bcrypt.hash(password, 10);

		const newUser = await users.insert({
			name,
			email,
			password: hashedPassword,
		});

		return res
			.status(201)
			.json({ message: 'Поьзователь успешно создан!', id: newUser._id });
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
});

app.post('/api/auth/login', async (req, res)=>{

	try {
		
			const {email, password} = req.body

			if(!email || !password){
				return res.status(422).json({message:'Please fill in all fields (email and password)'})
			}

			
			const user = await users.findOne({email})
			
			if(!user){
				return res.status(401).json({ message: 'Email or password is invalid' });
			}
			
			const passwordMatch = await bcrypt.compare(password, user.password)

			if(!passwordMatch){
				return res.status(401).json({ message: 'Email or password is invalid' });
			}

			const accessToken = jwt.sign({userId:user._id}, config.accessTokenSecret, { subject:'accessApi', expiresIn:'1h'})

			return res.status(200).json({
				id: user._id,
				name:user.name,
				email: user.email,
				accessToken
			})
	} catch (error) {
		return res.status(500).json({ message: error.message });
	}
})

app.get('/api/user/current', ensureAuthenticated, async(req,res)=>{
	try {
		const user = await users.findOne({_id:req.user.id})

		return res.status(200).json({
			id: user._id,
			name: user.name,
			email:user.email
		})

	} catch (error) {
		return res.status(401).json({message: error.message})
	}
})

async function ensureAuthenticated (req, res, next){
		const accessToken = req.headers.authorization

		if(!accessToken){
			return res.status(401).json({message: 'Access token not found'})
		}

		try {
			const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret)

			req.user = {id:decodedAccessToken.userId}

			next()
		} catch (error) {
			return res.status(401).json({message: 'Access token invalid or expired'})
		}
 }

app.listen(5000, () => {
	console.log('Server started on port 5000');
});
