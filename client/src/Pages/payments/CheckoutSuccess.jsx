import { useEffect } from 'react';
import Lottie from 'react-lottie'
import { useDispatch } from 'react-redux';
import { Link, useLocation, useNavigate } from 'react-router-dom'

import animationData from '../../lotties/payment-successful.json'
import { getProfile } from '../../redux/slices/AuthSlice';

function CheckoutSuccess() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { state } = useLocation();
    async function onLoad() {
        await dispatch(getProfile())
    }
    useEffect(() => {
        if (!state) {
            navigate("/")
        }
        onLoad()
    }, [])

    const defaultOptions = {
        loop: true,
        autoplay: true,
        animationData: animationData,
        rendererSettings: {
            preserveAspectRatio: "xMidYMid slice"
        }
    };
    return (
        <div className='h-screen flex justify-center items-center'>
            <div className='lg:w-1/3 w-11/12 m-auto bg-white rounded-lg shadow-lg flex flex-col gap-4 justify-center items-center pb-4'>
                <Lottie options={defaultOptions} height={300} width={300} />
                <p className='px-4 text-xl tracking-wider text-slate-500 text-center'>Congratulation. Welcome to the course</p>
                <Link className='btn btn-primary w-[90%]' to={'/'}>Go to home</Link>
            </div>
        </div>
    )
}

export default CheckoutSuccess
