import express from 'express';
import Datastore from 'nedb-promises';
import bcrypt from 'bcryptjs';

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

app.listen(5000, () => {
	console.log('Server started on port 5000');
});
