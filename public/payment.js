<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment - CV Tailor Pro</title>
    <link rel="stylesheet" href="style.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/feather-icons"></script>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
</head>
<body class="font-sans bg-gray-50">
    <custom-navbar></custom-navbar>

    <main class="min-h-screen">
        <!-- Payment Section -->
        <section class="py-16">
            <div class="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="text-center mb-12">
                    <h1 class="text-3xl font-extrabold text-gray-900 sm:text-4xl">
                        Complete Your Purchase
                    </h1>
                    <p class="mt-4 max-w-2xl text-xl text-gray-500 mx-auto">
                        We hope you only have to pay once. Good luck with your interview!
                    </p>
                </div>

                <div class="bg-white shadow-xl rounded-lg overflow-hidden">
                    <div class="p-6 sm:p-10">
                        <div class="flex items-start justify-between">
                            <div>
                                <h2 class="text-lg font-medium text-gray-900">
                                    CV Tailor Pro Monthly Plan
                                </h2>
                                <p class="mt-1 text-sm text-gray-500">
                                    Unlimited resume optimizations and job matching
                                </p>
                            </div>
                            <div class="text-right">
                                <p class="text-2xl font-bold text-gray-900">€2.99</p>
                                <p class="text-sm text-gray-500">per month</p>
                            </div>
                        </div>

                        <div class="mt-8 border-t border-gray-200 pt-8">
                            <h3 class="text-lg font-medium text-gray-900 mb-4">
                                Payment Information
                            </h3>
                            
                            <form>
                                <div class="grid grid-cols-1 gap-6">
                                    <div>
                                        <label for="card-number" class="block text-sm font-medium text-gray-700 mb-1">
                                            Card number
                                        </label>
                                        <div class="relative">
                                            <input type="text" id="card-number" name="card-number" autocomplete="cc-number" class="block w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500" placeholder="4242 4242 4242 4242">
                                            <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                                <i data-feather="credit-card" class="h-5 w-5 text-gray-400"></i>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="grid grid-cols-2 gap-6">
                                        <div>
                                            <label for="expiration-date" class="block text-sm font-medium text-gray-700 mb-1">
                                                Expiration date
                                            </label>
                                            <input type="text" id="expiration-date" name="expiration-date" autocomplete="cc-exp" class="block w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500" placeholder="MM / YY">
                                        </div>
                                        <div>
                                            <label for="cvc" class="block text-sm font-medium text-gray-700 mb-1">
                                                CVC
                                            </label>
                                            <div class="relative">
                                                <input type="text" id="cvc" name="cvc" autocomplete="cc-csc" class="block w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500" placeholder="123">
                                                <div class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                                                    <i data-feather="lock" class="h-5 w-5 text-gray-400"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div>
                                        <label for="name-on-card" class="block text-sm font-medium text-gray-700 mb-1">
                                            Name on card
                                        </label>
                                        <input type="text" id="name-on-card" name="name-on-card" autocomplete="cc-name" class="block w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500" placeholder="John Smith">
                                    </div>

                                    <div>
                                        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">
                                            Email address
                                        </label>
                                        <input type="email" id="email" name="email" autocomplete="email" class="block w-full px-4 py-3 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500" placeholder="you@example.com">
                                    </div>
                                </div>

                                <div class="mt-8 border-t border-gray-200 pt-6">
                                    <div class="flex items-center">
                                        <input id="terms" name="terms" type="checkbox" class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                        <label for="terms" class="ml-2 block text-sm text-gray-700">
                                            I agree to the <a href="#" class="text-blue-600 hover:text-blue-500">Terms of Service</a> and <a href="#" class="text-blue-600 hover:text-blue-500">Privacy Policy</a>
                                        </label>
                                    </div>
                                    <div class="mt-6">
                                        <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition duration-150">
                                            Complete Payment
                                        </button>
                                    </div>
                                    <p class="mt-4 text-sm text-gray-500 text-center">
                                        You won't be charged until the end of your 7-day free trial.
                                    </p>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <div class="mt-8 bg-white shadow rounded-lg overflow-hidden">
                    <div class="p-6 sm:p-8">
                        <h3 class="text-lg font-medium text-gray-900 mb-4">
                            What's Included
                        </h3>
                        <ul class="space-y-3">
                            <li class="flex items-start">
                                <div class="flex-shrink-0">
                                    <i data-feather="check" class="h-5 w-5 text-green-500"></i>
                                </div>
                                <p class="ml-3 text-base text-gray-600">
                                    Unlimited resume optimizations for any job posting
                                </p>
                            </li>
                            <li class="flex items-start">
                                <div class="flex-shrink-0">
                                    <i data-feather="check" class="h-5 w-5 text-green-500"></i>
                                </div>
                                <p class="ml-3 text-base text-gray-600">
                                    Personalized job matching based on your optimized profile
                                </p>
                            </li>
                            <li class="flex items-start">
                                <div class="flex-shrink-0">
                                    <i data-feather="check" class="h-5 w-5 text-green-500"></i>
                                </div>
                                <p class="ml-3 text-base text-gray-600">
                                    ATS optimization reports to track your resume's performance
                                </p>
                            </li>
                            <li class="flex items-start">
                                <div class="flex-shrink-0">
                                    <i data-feather="check" class="h-5 w-5 text-green-500"></i>
                                </div>
                                <p class="ml-3 text-base text-gray-600">
                                    Priority customer support to help with any questions
                                </p>
                            </li>
                            <li class="flex items-start">
                                <div class="flex-shrink-0">
                                    <i data-feather="check" class="h-5 w-5 text-green-500"></i>
                                </div>
                                <p class="ml-3 text-base text-gray-600">
                                    Download in multiple formats including PDF and DOCX
                                </p>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <custom-footer></custom-footer>

    <script src="components/navbar.js"></script>
    <script src="components/footer.js"></script>
    <script src="script.js"></script>
    <script>
        feather.replace();
    </script>
</body>
</html>